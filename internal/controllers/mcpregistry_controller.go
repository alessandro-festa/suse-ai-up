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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

const (
	// registryLabelKey carries the owning MCPRegistry CR name on every
	// child MCPServer the reconciler manages. Used as the primary list
	// selector for desired-vs-observed reconciliation.
	registryLabelKey = "mcp.suse.com/registry"

	// serverNameLabelKey is the sanitized server displayName, used by
	// MCPServerReconciler to group siblings across registries when
	// resolving name conflicts.
	serverNameLabelKey = "mcp.suse.com/server-name"

	// defaultRegistryRefresh is the resync interval when MCPRegistrySpec
	// leaves RefreshInterval unset. Matches the previous in-process
	// behavior in pkg/services/registry/sync.go.
	defaultRegistryRefresh = 5 * time.Minute

	// registryFetchTimeout matches loader.defaultRegistryTimeout so the
	// operator path behaves like the legacy HTTP loader.
	registryFetchTimeout = 30 * time.Second
)

// MCPRegistryReconciler resolves an MCPRegistry's Spec.Source (URL,
// ConfigMap, or Inline) into a set of owned MCPServer child CRs. It owns
// only the child CRs; MCPServerReconciler is responsible for conflict
// resolution across registries.
type MCPRegistryReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// HTTPClient is injected for testability; defaults to a client with the
	// registryFetchTimeout above when nil at SetupWithManager time.
	HTTPClient *http.Client
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpregistries,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpregistries/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpregistries/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch

// Reconcile drives the MCPRegistry toward its declared state.
//
// The loop is idempotent: source bytes are re-fetched, parsed, and the
// resulting child set is compared label-by-label against what's in the
// cluster. Extra children are deleted; missing children are created;
// drift is corrected via controllerutil.CreateOrUpdate. OwnerReferences
// on the children mean MCPRegistry deletion cascades automatically.
func (r *MCPRegistryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var registry mcpv1alpha1.MCPRegistry
	if err := r.Get(ctx, req.NamespacedName, &registry); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MCPRegistry: %w", err)
	}

	specs, names, warnings, isInline, srcErr := r.resolveSource(ctx, &registry)
	if srcErr != nil {
		logger.Info("MCPRegistry source resolution failed", "registry", req.NamespacedName, "error", srcErr.error)
		return r.patchStatus(ctx, &registry, func(s *mcpv1alpha1.MCPRegistryStatus) {
			s.Phase = mcpv1alpha1.MCPRegistryPhaseFailed
			s.SyncError = srcErr.error.Error()
			s.ObservedGeneration = registry.Generation
			setMetaCondition(&s.Conditions, registry.Generation,
				mcpv1alpha1.MCPRegistryConditionSynced, metav1.ConditionFalse,
				srcErr.reason, srcErr.error.Error())
			setMetaCondition(&s.Conditions, registry.Generation,
				mcpv1alpha1.MCPRegistryConditionReady, metav1.ConditionFalse,
				srcErr.reason, "Source could not be loaded.")
		}, requeueAfterFor(&registry, isInline))
	}

	desired := buildChildSet(&registry, specs, names)

	// List existing children labeled with this registry so we can compute
	// the diff. We rely on the label rather than owner-ref filtering
	// because the operator API client doesn't expose owner-ref selectors
	// directly.
	var existing mcpv1alpha1.MCPServerList
	if err := r.List(ctx, &existing,
		client.InNamespace(registry.Namespace),
		client.MatchingLabels{registryLabelKey: registry.Name},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing child MCPServers: %w", err)
	}

	desiredByName := make(map[string]*mcpv1alpha1.MCPServer, len(desired))
	for i := range desired {
		desiredByName[desired[i].Name] = desired[i]
	}

	// Delete obsolete children.
	for i := range existing.Items {
		child := &existing.Items[i]
		if _, keep := desiredByName[child.Name]; keep {
			continue
		}
		if err := r.Delete(ctx, child); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("deleting obsolete MCPServer %s: %w", child.Name, err)
		}
	}

	// Upsert desired children + stamp Status.Priority / SourceRegistry.
	for _, child := range desired {
		if err := controllerutil.SetControllerReference(&registry, child, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("setting owner ref on %s: %w", child.Name, err)
		}

		applied := &mcpv1alpha1.MCPServer{
			ObjectMeta: metav1.ObjectMeta{Name: child.Name, Namespace: child.Namespace},
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, applied, func() error {
			applied.Labels = child.Labels
			applied.OwnerReferences = child.OwnerReferences
			applied.Spec = child.Spec
			return nil
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf("upserting MCPServer %s: %w", child.Name, err)
		}

		if applied.Status.Priority != registry.Spec.Priority || applied.Status.SourceRegistry != registry.Name {
			original := applied.DeepCopy()
			applied.Status.Priority = registry.Spec.Priority
			applied.Status.SourceRegistry = registry.Name
			if err := r.Status().Patch(ctx, applied, client.MergeFrom(original)); err != nil {
				return ctrl.Result{}, fmt.Errorf("patching MCPServer %s status: %w", child.Name, err)
			}
		}
	}

	observedCount := int32(len(desired))
	now := metav1.Now()
	return r.patchStatus(ctx, &registry, func(s *mcpv1alpha1.MCPRegistryStatus) {
		s.Phase = mcpv1alpha1.MCPRegistryPhaseReady
		s.LastSyncTime = &now
		s.ObservedServerCount = observedCount
		s.SyncError = ""
		s.ObservedGeneration = registry.Generation
		syncedMsg := fmt.Sprintf("Loaded %d MCPServer entries.", observedCount)
		if len(warnings) > 0 {
			syncedMsg += " Warnings: " + strings.Join(warnings, "; ")
		}
		setMetaCondition(&s.Conditions, registry.Generation,
			mcpv1alpha1.MCPRegistryConditionSynced, metav1.ConditionTrue,
			"InSync", syncedMsg)
		setMetaCondition(&s.Conditions, registry.Generation,
			mcpv1alpha1.MCPRegistryConditionReady, metav1.ConditionTrue,
			"SourceLoaded", "Registry source loaded and child MCPServer CRs reconciled.")
	}, requeueAfterFor(&registry, isInline))
}

// sourceError carries both a wrapped error and a stable Reason string used
// for the Synced condition. Sentinel-style so callers don't have to map
// errors back to reasons by string-matching.
type sourceError struct {
	reason string
	error  error
}

// resolveSource pulls bytes from whichever of URL / ConfigMapRef / Inline is
// set, parses (if needed), and returns the resulting spec list. The
// isInline flag is propagated to the caller so periodic resync can be
// skipped for inline sources.
func (r *MCPRegistryReconciler) resolveSource(ctx context.Context, registry *mcpv1alpha1.MCPRegistry) (specs []mcpv1alpha1.MCPServerSpec, names []string, warnings []string, isInline bool, srcErr *sourceError) {
	src := registry.Spec.Source

	switch {
	case len(src.Inline) > 0:
		isInline = true
		specs = make([]mcpv1alpha1.MCPServerSpec, len(src.Inline))
		names = make([]string, len(src.Inline))
		for i, s := range src.Inline {
			specs[i] = s
			n := s.DisplayName
			if n == "" {
				n = fmt.Sprintf("inline-%d", i)
			}
			names[i] = n
		}
		return specs, names, nil, true, nil

	case src.URL != "":
		data, err := r.fetchURL(ctx, src.URL)
		if err != nil {
			return nil, nil, nil, false, &sourceError{reason: "FetchFailed", error: err}
		}
		specs, names, warnings, err = ParseRegistryYAML(data)
		if err != nil {
			return nil, nil, nil, false, &sourceError{reason: "ParseFailed", error: err}
		}
		return specs, names, warnings, false, nil

	case src.ConfigMapRef != nil:
		var cm corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Namespace: registry.Namespace, Name: src.ConfigMapRef.Name}, &cm); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil, nil, false, &sourceError{
					reason: "ConfigMapMissing",
					error:  fmt.Errorf("ConfigMap %s/%s not found", registry.Namespace, src.ConfigMapRef.Name),
				}
			}
			return nil, nil, nil, false, &sourceError{reason: "ConfigMapReadFailed", error: err}
		}
		if len(cm.Data) == 0 {
			return nil, nil, nil, false, &sourceError{
				reason: "ConfigMapEmpty",
				error:  fmt.Errorf("ConfigMap %s/%s has no data keys", registry.Namespace, src.ConfigMapRef.Name),
			}
		}
		var key string
		var data string
		for k, v := range cm.Data {
			if key == "" || k < key { // deterministic pick: alphabetically-first key
				key, data = k, v
			}
		}
		specs, names, warnings, err := ParseRegistryYAML([]byte(data))
		if err != nil {
			return nil, nil, nil, false, &sourceError{reason: "ParseFailed", error: err}
		}
		if len(cm.Data) > 1 {
			warnings = append(warnings, fmt.Sprintf("ConfigMap has %d keys; using %q", len(cm.Data), key))
		}
		return specs, names, warnings, false, nil

	default:
		return nil, nil, nil, false, &sourceError{
			reason: "NoSource",
			error:  fmt.Errorf("MCPRegistry.Spec.Source has none of url, configMapRef, inline set"),
		}
	}
}

func (r *MCPRegistryReconciler) fetchURL(ctx context.Context, url string) ([]byte, error) {
	cli := r.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: registryFetchTimeout}
	}
	reqCtx, cancel := context.WithTimeout(ctx, registryFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// buildChildSet projects parsed specs into the deterministic set of
// MCPServer CRs the reconciler will upsert. Sanitized names + dedup keep
// the resulting set stable across re-syncs.
func buildChildSet(registry *mcpv1alpha1.MCPRegistry, specs []mcpv1alpha1.MCPServerSpec, names []string) []*mcpv1alpha1.MCPServer {
	out := make([]*mcpv1alpha1.MCPServer, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for i, spec := range specs {
		base := sanitizeName(names[i])
		if base == "" {
			continue
		}
		childName := registry.Name + "-" + base
		if seen[childName] {
			continue // skip duplicate; parser warning will surface count
		}
		seen[childName] = true

		serverLabel := sanitizeName(spec.DisplayName)
		if serverLabel == "" {
			serverLabel = base
		}

		child := &mcpv1alpha1.MCPServer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      childName,
				Namespace: registry.Namespace,
				Labels: map[string]string{
					registryLabelKey:   registry.Name,
					serverNameLabelKey: serverLabel,
				},
			},
			Spec: spec,
		}
		out = append(out, child)
	}
	return out
}

func requeueAfterFor(registry *mcpv1alpha1.MCPRegistry, isInline bool) ctrl.Result {
	if isInline {
		return ctrl.Result{}
	}
	if registry.Spec.RefreshInterval != nil && registry.Spec.RefreshInterval.Duration > 0 {
		return ctrl.Result{RequeueAfter: registry.Spec.RefreshInterval.Duration}
	}
	return ctrl.Result{RequeueAfter: defaultRegistryRefresh}
}

func (r *MCPRegistryReconciler) patchStatus(ctx context.Context, registry *mcpv1alpha1.MCPRegistry, mutate func(*mcpv1alpha1.MCPRegistryStatus), result ctrl.Result) (ctrl.Result, error) {
	original := registry.DeepCopy()
	mutate(&registry.Status)
	if err := r.Status().Patch(ctx, registry, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching MCPRegistry status: %w", err)
	}
	return result, nil
}

// SetupWithManager registers the reconciler. The Watches on ConfigMaps
// enqueues registries that reference the changed ConfigMap by name so
// source-of-truth edits propagate without manual annotation gymnastics.
func (r *MCPRegistryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.MCPRegistry{}).
		Owns(&mcpv1alpha1.MCPServer{}).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapConfigMapToRegistries)).
		Named("mcpregistry").
		Complete(r)
}

func (r *MCPRegistryReconciler) mapConfigMapToRegistries(ctx context.Context, obj client.Object) []reconcile.Request {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil
	}
	var registries mcpv1alpha1.MCPRegistryList
	if err := r.List(ctx, &registries, client.InNamespace(cm.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range registries.Items {
		ref := registries.Items[i].Spec.Source.ConfigMapRef
		if ref != nil && ref.Name == cm.Name {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: registries.Items[i].Namespace,
				Name:      registries.Items[i].Name,
			}})
		}
	}
	return out
}
