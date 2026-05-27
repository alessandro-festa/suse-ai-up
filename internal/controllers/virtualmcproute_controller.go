/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services/virtualmcp"
)

// VirtualMCPRouteReconciler resolves the source/ACL references of a
// VirtualMCPRoute, asks the CapabilityProvider for each source's catalog,
// applies selectors + rewrites, and reflects the resulting route (Ready
// or Degraded) into the shared in-process RouteStore. §2.4 will swap the
// NoOp Provider injected by cmd/manager for the real capability-cache-
// backed implementation; the reconciler shape stays the same.
type VirtualMCPRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Store is the in-process route table the reconciler reflects
	// Ready/Degraded routes into. Nil is tolerated for envtest-style
	// suites that don't exercise the data plane.
	Store virtualmcp.RouteStore

	// Provider supplies per-source catalogs used to populate
	// Status.ResolvedEntries. Nil is treated as "always unavailable" —
	// same behavior as virtualmcp.NewNoOpCapabilityProvider.
	Provider virtualmcp.CapabilityProvider
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=virtualmcproutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=virtualmcproutes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=virtualmcproutes/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=adapters,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=routeassignments,verbs=get;list;watch

// Reconcile resolves a single VirtualMCPRoute.
func (r *VirtualMCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var route mcpv1alpha1.VirtualMCPRoute
	if err := r.Get(ctx, req.NamespacedName, &route); err != nil {
		if apierrors.IsNotFound(err) {
			r.removeFromStore(ctx, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching VirtualMCPRoute: %w", err)
	}

	resolved, missingSources, degradedSources, sourceDiags, err := r.resolveSources(ctx, &route)
	if err != nil {
		return ctrl.Result{}, err
	}

	missingACLs, err := r.validateACLs(ctx, &route)
	if err != nil {
		return ctrl.Result{}, err
	}

	entries, collisions := flattenSources(resolved)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Name < entries[j].Name
	})

	exposed := route.Spec.ExposedAs
	if exposed == "" {
		exposed = route.Name
	}
	endpointURL := "/api/v1/vroutes/" + exposed + "/mcp"

	now := metav1.Now()
	original := route.DeepCopy()

	route.Status.EndpointURL = endpointURL
	route.Status.ResolvedEntries = entries
	route.Status.EntryCount = int32(len(entries))
	route.Status.LastResolvedTime = &now
	route.Status.ObservedGeneration = route.Generation

	phase, readyStatus, readyReason, readyMsg := computePhase(missingSources, missingACLs, degradedSources, collisions, entries)
	route.Status.Phase = phase

	setMetaCondition(&route.Status.Conditions, route.Generation,
		mcpv1alpha1.VirtualMCPRouteConditionReady, readyStatus, readyReason, readyMsg)

	sourceMissingStatus := metav1.ConditionFalse
	sourceMissingReason := "AllSourcesResolved"
	sourceMissingMsg := "All referenced Adapters/MCPServers exist."
	if len(missingSources) > 0 {
		sourceMissingStatus = metav1.ConditionTrue
		sourceMissingReason = "SourceMissing"
		sourceMissingMsg = "Missing sources: " + strings.Join(missingSources, ", ")
	}
	setMetaCondition(&route.Status.Conditions, route.Generation,
		mcpv1alpha1.VirtualMCPRouteConditionSourceMissing, sourceMissingStatus, sourceMissingReason, sourceMissingMsg)

	conflictStatus := metav1.ConditionFalse
	conflictReason := "NoConflict"
	conflictMsg := "No exposed-name collisions across sources."
	if len(collisions) > 0 {
		conflictStatus = metav1.ConditionTrue
		conflictReason = "EntryCollision"
		conflictMsg = "Dropped colliding entries: " + strings.Join(collisions, ", ")
	}
	setMetaCondition(&route.Status.Conditions, route.Generation,
		mcpv1alpha1.VirtualMCPRouteConditionConflict, conflictStatus, conflictReason, conflictMsg)

	if err := r.Status().Patch(ctx, &route, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching VirtualMCPRoute status: %w", err)
	}

	if phase == mcpv1alpha1.VirtualMCPRoutePhaseFailed {
		r.removeFromStore(ctx, route.Name)
	} else {
		r.reflectToStore(ctx, &route)
	}

	if len(sourceDiags) > 0 {
		logger.V(1).Info("source diagnostics", "route", req.NamespacedName, "diagnostics", sourceDiags)
	}

	return ctrl.Result{}, nil
}

// resolveSources walks Spec.Sources, gets each referenced CR, queries the
// CapabilityProvider, applies selectors + rewrites, and returns the
// per-source resolved entries along with bookkeeping for missing /
// degraded sources and any selector diagnostics.
func (r *VirtualMCPRouteReconciler) resolveSources(ctx context.Context, route *mcpv1alpha1.VirtualMCPRoute) (resolved []resolvedSource, missing, degraded, diagnostics []string, err error) {
	provider := r.Provider
	if provider == nil {
		provider = virtualmcp.NewNoOpCapabilityProvider()
	}

	for i, src := range route.Spec.Sources {
		hasAdapter := src.AdapterRef != nil && src.AdapterRef.Name != ""
		hasServer := src.MCPServerRef != nil && src.MCPServerRef.Name != ""
		if hasAdapter == hasServer {
			missing = append(missing, fmt.Sprintf("sources[%d]: exactly one of adapterRef/mcpServerRef required", i))
			continue
		}

		rs := resolvedSource{}
		var catalog *virtualmcp.Catalog

		if hasAdapter {
			rs.SourceAdapter = src.AdapterRef.Name
			var adapter mcpv1alpha1.Adapter
			if getErr := r.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: src.AdapterRef.Name}, &adapter); getErr != nil {
				if apierrors.IsNotFound(getErr) {
					missing = append(missing, "adapter/"+src.AdapterRef.Name)
					continue
				}
				return nil, nil, nil, nil, fmt.Errorf("fetching Adapter %s: %w", src.AdapterRef.Name, getErr)
			}
			c, cErr := provider.AdapterCatalog(ctx, route.Namespace, src.AdapterRef.Name)
			if cErr != nil && !errors.Is(cErr, virtualmcp.ErrCatalogUnavailable) {
				return nil, nil, nil, nil, fmt.Errorf("fetching adapter catalog %s: %w", src.AdapterRef.Name, cErr)
			}
			if errors.Is(cErr, virtualmcp.ErrCatalogUnavailable) {
				degraded = append(degraded, "adapter/"+src.AdapterRef.Name)
			}
			catalog = c
		} else {
			rs.SourceMCPServer = src.MCPServerRef.Name
			var server mcpv1alpha1.MCPServer
			if getErr := r.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: src.MCPServerRef.Name}, &server); getErr != nil {
				if apierrors.IsNotFound(getErr) {
					missing = append(missing, "mcpserver/"+src.MCPServerRef.Name)
					continue
				}
				return nil, nil, nil, nil, fmt.Errorf("fetching MCPServer %s: %w", src.MCPServerRef.Name, getErr)
			}
			c, cErr := provider.MCPServerCatalog(ctx, route.Namespace, src.MCPServerRef.Name)
			if cErr != nil && !errors.Is(cErr, virtualmcp.ErrCatalogUnavailable) {
				return nil, nil, nil, nil, fmt.Errorf("fetching mcpserver catalog %s: %w", src.MCPServerRef.Name, cErr)
			}
			if errors.Is(cErr, virtualmcp.ErrCatalogUnavailable) {
				degraded = append(degraded, "mcpserver/"+src.MCPServerRef.Name)
			}
			catalog = c
		}

		// Catalog may be nil under the NoOp provider; that's fine —
		// selectors return empty matches against an empty name list.
		var toolNames, resourceNames, promptNames []string
		if catalog != nil {
			toolNames = catalogNames(catalog.Tools)
			resourceNames = catalogNames(catalog.Resources)
			promptNames = catalogNames(catalog.Prompts)
		}

		toolMatches, td := applySelector(toolNames, src.Tools)
		resourceMatches, rd := applySelector(resourceNames, src.Resources)
		promptMatches, pd := applySelector(promptNames, src.Prompts)
		for _, d := range []string{td, rd, pd} {
			if d != "" {
				diagnostics = append(diagnostics, fmt.Sprintf("sources[%d]: %s", i, d))
			}
		}

		rs.Tools = applyRewrite(toolMatches, src.Rewrite)
		rs.Resources = applyRewrite(resourceMatches, src.Rewrite)
		rs.Prompts = applyRewrite(promptMatches, src.Rewrite)
		resolved = append(resolved, rs)
	}

	return resolved, missing, degraded, diagnostics, nil
}

// validateACLs only checks that each referenced RouteAssignment exists.
// Actual subject expansion + enforcement is §2.3e's job (RouteAssignment
// reconciler) and §2.4's (HTTP shim).
func (r *VirtualMCPRouteReconciler) validateACLs(ctx context.Context, route *mcpv1alpha1.VirtualMCPRoute) ([]string, error) {
	var missing []string
	for _, ref := range route.Spec.ACL {
		if ref.Name == "" {
			missing = append(missing, "routeassignment/<unnamed>")
			continue
		}
		var ra mcpv1alpha1.RouteAssignment
		if err := r.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: ref.Name}, &ra); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, "routeassignment/"+ref.Name)
				continue
			}
			return nil, fmt.Errorf("fetching RouteAssignment %s: %w", ref.Name, err)
		}
	}
	return missing, nil
}

// computePhase rolls up the per-source / per-ACL findings into the
// Phase + Ready-condition values the reconciler patches onto Status.
// The precedence — Failed > Degraded > Ready — matches the API doc on
// VirtualMCPRoutePhase.
func computePhase(missingSources, missingACLs, degradedSources, collisions []string, entries []mcpv1alpha1.ResolvedEntry) (mcpv1alpha1.VirtualMCPRoutePhase, metav1.ConditionStatus, string, string) {
	if len(missingSources) > 0 {
		return mcpv1alpha1.VirtualMCPRoutePhaseFailed,
			metav1.ConditionFalse,
			"SourceMissing",
			"Route cannot be served: " + strings.Join(missingSources, ", ")
	}
	if len(missingACLs) > 0 {
		return mcpv1alpha1.VirtualMCPRoutePhaseDegraded,
			metav1.ConditionFalse,
			"ACLMissing",
			"ACL references not found: " + strings.Join(missingACLs, ", ")
	}
	if len(collisions) > 0 {
		return mcpv1alpha1.VirtualMCPRoutePhaseDegraded,
			metav1.ConditionFalse,
			"EntryCollision",
			"Dropped colliding entries: " + strings.Join(collisions, ", ")
	}
	if len(degradedSources) > 0 {
		return mcpv1alpha1.VirtualMCPRoutePhaseDegraded,
			metav1.ConditionFalse,
			"CatalogUnavailable",
			"Capability provider returned no catalog for: " + strings.Join(degradedSources, ", ") +
				" (real provider arrives in §2.4)"
	}
	if len(entries) == 0 {
		return mcpv1alpha1.VirtualMCPRoutePhaseDegraded,
			metav1.ConditionFalse,
			"NoEntries",
			"Route resolved zero entries; check source selectors."
	}
	return mcpv1alpha1.VirtualMCPRoutePhaseReady,
		metav1.ConditionTrue,
		"Resolved",
		fmt.Sprintf("Route serving %d entries.", len(entries))
}

func (r *VirtualMCPRouteReconciler) reflectToStore(ctx context.Context, route *mcpv1alpha1.VirtualMCPRoute) {
	if r.Store == nil {
		return
	}
	model := routeToModel(route)
	if err := r.Store.UpsertRoute(model); err != nil {
		log.FromContext(ctx).Error(err, "route store upsert failed", "route", route.Name)
	}
}

func (r *VirtualMCPRouteReconciler) removeFromStore(ctx context.Context, id string) {
	if r.Store == nil {
		return
	}
	if err := r.Store.DeleteRoute(id); err != nil {
		log.FromContext(ctx).Error(err, "route store delete failed", "route", id)
	}
}

// routeToModel projects a VirtualMCPRoute into the legacy models.MCPServer
// shape the HTTP shim already speaks. Lossy by design — the route only
// needs to look like an MCP server to clients; per-source provenance lives
// on Status.ResolvedEntries, not in the model.
func routeToModel(route *mcpv1alpha1.VirtualMCPRoute) *models.MCPServer {
	exposed := route.Spec.ExposedAs
	if exposed == "" {
		exposed = route.Name
	}
	model := &models.MCPServer{
		ID:           route.Name,
		Name:         exposed,
		Description:  route.Spec.Description,
		URL:          route.Status.EndpointURL,
		DiscoveredAt: time.Now(),
		Meta: map[string]interface{}{
			"source":             "virtualmcproute-cr",
			"sourceVirtualRoute": route.Name,
		},
	}
	for _, e := range route.Status.ResolvedEntries {
		if e.Kind != mcpv1alpha1.ResolvedEntryKindTool {
			continue
		}
		model.Tools = append(model.Tools, models.MCPTool{Name: e.Name})
	}
	return model
}

// SetupWithManager wires the watches that re-enqueue a route on changes
// to its referenced Adapters / MCPServers / RouteAssignments. Pattern
// lifted from MCPRegistryReconciler.mapConfigMapToRegistries.
func (r *VirtualMCPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.VirtualMCPRoute{}).
		Watches(&mcpv1alpha1.Adapter{}, handler.EnqueueRequestsFromMapFunc(r.mapAdapterToRoutes)).
		Watches(&mcpv1alpha1.MCPServer{}, handler.EnqueueRequestsFromMapFunc(r.mapMCPServerToRoutes)).
		Watches(&mcpv1alpha1.RouteAssignment{}, handler.EnqueueRequestsFromMapFunc(r.mapAssignmentToRoutes)).
		Named("virtualmcproute").
		Complete(r)
}

func (r *VirtualMCPRouteReconciler) mapAdapterToRoutes(ctx context.Context, obj client.Object) []reconcile.Request {
	adapter, ok := obj.(*mcpv1alpha1.Adapter)
	if !ok {
		return nil
	}
	return r.listRoutesMatching(ctx, adapter.Namespace, func(route *mcpv1alpha1.VirtualMCPRoute) bool {
		for _, src := range route.Spec.Sources {
			if src.AdapterRef != nil && src.AdapterRef.Name == adapter.Name {
				return true
			}
		}
		return false
	})
}

func (r *VirtualMCPRouteReconciler) mapMCPServerToRoutes(ctx context.Context, obj client.Object) []reconcile.Request {
	server, ok := obj.(*mcpv1alpha1.MCPServer)
	if !ok {
		return nil
	}
	return r.listRoutesMatching(ctx, server.Namespace, func(route *mcpv1alpha1.VirtualMCPRoute) bool {
		for _, src := range route.Spec.Sources {
			if src.MCPServerRef != nil && src.MCPServerRef.Name == server.Name {
				return true
			}
		}
		return false
	})
}

func (r *VirtualMCPRouteReconciler) mapAssignmentToRoutes(ctx context.Context, obj client.Object) []reconcile.Request {
	ra, ok := obj.(*mcpv1alpha1.RouteAssignment)
	if !ok {
		return nil
	}
	return r.listRoutesMatching(ctx, ra.Namespace, func(route *mcpv1alpha1.VirtualMCPRoute) bool {
		for _, ref := range route.Spec.ACL {
			if ref.Name == ra.Name {
				return true
			}
		}
		return false
	})
}

func (r *VirtualMCPRouteReconciler) listRoutesMatching(ctx context.Context, namespace string, match func(*mcpv1alpha1.VirtualMCPRoute) bool) []reconcile.Request {
	var routes mcpv1alpha1.VirtualMCPRouteList
	if err := r.List(ctx, &routes, client.InNamespace(namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range routes.Items {
		if match(&routes.Items[i]) {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: routes.Items[i].Namespace,
				Name:      routes.Items[i].Name,
			}})
		}
	}
	return out
}
