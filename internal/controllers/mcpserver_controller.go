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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// MCPServerReconciler resolves cross-registry name conflicts among
// MCPServer CRs and reflects the active (winning) entries into a shared
// in-process store. Today only the operator binary uses the store; the
// HTTP shim swap in §2.4 will share this same instance with the legacy
// data plane.
type MCPServerReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Store is the in-process MCP server cache active entries are
	// reflected into. Nil is tolerated (logs and skips reflection) so
	// envtest-style suites that don't need the data plane can omit it.
	Store clients.MCPServerStore
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=mcpservers/finalizers,verbs=update

// Reconcile runs conflict resolution for a single MCPServer.
//
// "Conflict" here means: more than one MCPServer in the namespace shares
// a server-name label (sanitized DisplayName). The winner is the entry
// with the highest Status.Priority (copied from the owning MCPRegistry by
// MCPRegistryReconciler); ties are broken by oldest CreationTimestamp,
// then lexicographic Name. Winners get Phase=Active and are written to
// the in-process store; losers get Phase=Conflict and are removed.
func (r *MCPServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var server mcpv1alpha1.MCPServer
	if err := r.Get(ctx, req.NamespacedName, &server); err != nil {
		if apierrors.IsNotFound(err) {
			// Drop from the store too; the in-process cache is keyed on
			// the CR name and the watch fires once on deletion.
			r.removeFromStore(ctx, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MCPServer: %w", err)
	}

	groupKey := serverGroupKey(&server)
	if groupKey == "" {
		// No DisplayName / fallback label means this server is unaddressable
		// for conflict resolution. Treat as a single-entry group: just
		// reflect it.
		return r.markActive(ctx, &server, "no group key; treated as singleton")
	}

	var siblings mcpv1alpha1.MCPServerList
	if err := r.List(ctx, &siblings,
		client.InNamespace(req.Namespace),
		client.MatchingLabels{serverNameLabelKey: groupKey},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing siblings: %w", err)
	}

	winnerIdx := pickWinner(siblings.Items)
	if winnerIdx < 0 {
		// Label-driven list returned empty — the only way this can happen
		// is a label-vs-spec mismatch on this CR. Fall back to singleton.
		logger.V(1).Info("sibling list empty for non-empty group key; treating as singleton",
			"name", req.NamespacedName, "groupKey", groupKey)
		return r.markActive(ctx, &server, "siblings list empty")
	}

	winner := &siblings.Items[winnerIdx]
	if winner.Name == server.Name && winner.Namespace == server.Namespace {
		return r.markActive(ctx, &server,
			fmt.Sprintf("won group %q with priority %d", groupKey, server.Status.Priority))
	}
	return r.markConflict(ctx, &server, winner)
}

func (r *MCPServerReconciler) markActive(ctx context.Context, server *mcpv1alpha1.MCPServer, reasonMsg string) (ctrl.Result, error) {
	original := server.DeepCopy()
	server.Status.Phase = mcpv1alpha1.MCPServerPhaseActive
	server.Status.ObservedGeneration = server.Generation
	setMetaCondition(&server.Status.Conditions, server.Generation,
		mcpv1alpha1.MCPServerConditionReady, metav1.ConditionTrue,
		"Active", reasonMsg)
	setMetaCondition(&server.Status.Conditions, server.Generation,
		mcpv1alpha1.MCPServerConditionConflict, metav1.ConditionFalse,
		"NoConflict", "Server is the unique or highest-priority entry for its name.")
	if err := r.Status().Patch(ctx, server, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching MCPServer status: %w", err)
	}
	r.reflectToStore(ctx, server)
	return ctrl.Result{}, nil
}

func (r *MCPServerReconciler) markConflict(ctx context.Context, server *mcpv1alpha1.MCPServer, winner *mcpv1alpha1.MCPServer) (ctrl.Result, error) {
	original := server.DeepCopy()
	server.Status.Phase = mcpv1alpha1.MCPServerPhaseConflict
	server.Status.ObservedGeneration = server.Generation
	msg := fmt.Sprintf("Server %q wins with priority %d (this entry priority %d).",
		winner.Name, winner.Status.Priority, server.Status.Priority)
	setMetaCondition(&server.Status.Conditions, server.Generation,
		mcpv1alpha1.MCPServerConditionConflict, metav1.ConditionTrue,
		"LosingPriority", msg)
	setMetaCondition(&server.Status.Conditions, server.Generation,
		mcpv1alpha1.MCPServerConditionReady, metav1.ConditionFalse,
		"Conflicted", "Server is suppressed by a higher-priority sibling.")
	if err := r.Status().Patch(ctx, server, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching MCPServer status: %w", err)
	}
	r.removeFromStore(ctx, server.Name)
	return ctrl.Result{}, nil
}

// reflectToStore mirrors an Active MCPServer into the in-memory store
// keyed by the CR name. The mapping is intentionally minimal — the
// store is the operator's transient cache, not its source of truth; the
// CR is.
func (r *MCPServerReconciler) reflectToStore(ctx context.Context, server *mcpv1alpha1.MCPServer) {
	if r.Store == nil {
		return
	}
	logger := log.FromContext(ctx)
	model := mcpServerToModel(server)

	existing, err := r.Store.GetMCPServer(server.Name)
	if err == nil && existing != nil {
		if err := r.Store.UpdateMCPServer(server.Name, model); err != nil {
			logger.Error(err, "store update failed", "name", server.Name)
		}
		return
	}
	if !errors.Is(err, clients.ErrNotFound) && err != nil {
		logger.Error(err, "store lookup failed", "name", server.Name)
		return
	}
	if err := r.Store.CreateMCPServer(model); err != nil {
		logger.Error(err, "store create failed", "name", server.Name)
	}
}

func (r *MCPServerReconciler) removeFromStore(ctx context.Context, name string) {
	if r.Store == nil {
		return
	}
	if err := r.Store.DeleteMCPServer(name); err != nil && !errors.Is(err, clients.ErrNotFound) {
		log.FromContext(ctx).Error(err, "store delete failed", "name", name)
	}
}

// serverGroupKey returns the value used to look up siblings. Prefers the
// label set by MCPRegistryReconciler (stable, sanitized) and falls back
// to sanitizing DisplayName for standalone CRs that lack the label.
func serverGroupKey(server *mcpv1alpha1.MCPServer) string {
	if v, ok := server.Labels[serverNameLabelKey]; ok && v != "" {
		return v
	}
	return sanitizeName(server.Spec.DisplayName)
}

// pickWinner returns the index of the MCPServer that should be Active
// among siblings sharing a displayName. Higher Status.Priority wins;
// ties → older CreationTimestamp; further ties → lexicographic Name.
// Returns -1 only if siblings is empty.
func pickWinner(siblings []mcpv1alpha1.MCPServer) int {
	if len(siblings) == 0 {
		return -1
	}
	winner := 0
	for i := 1; i < len(siblings); i++ {
		if betterWinner(&siblings[i], &siblings[winner]) {
			winner = i
		}
	}
	return winner
}

func betterWinner(candidate, current *mcpv1alpha1.MCPServer) bool {
	if candidate.Status.Priority != current.Status.Priority {
		return candidate.Status.Priority > current.Status.Priority
	}
	ct, cur := candidate.CreationTimestamp.Time, current.CreationTimestamp.Time
	if !ct.Equal(cur) {
		return ct.Before(cur)
	}
	return candidate.Name < current.Name
}

// mcpServerToModel projects the CR shape into the legacy in-memory store
// shape. Lossy by design — the store predates CRDs and only needs the
// fields the HTTP path reads back. §2.4 will revisit this once the data
// plane is consolidated.
func mcpServerToModel(server *mcpv1alpha1.MCPServer) *models.MCPServer {
	out := &models.MCPServer{
		ID:           server.Name,
		Name:         server.Spec.DisplayName,
		Image:        server.Spec.Image,
		Description:  server.Spec.Description,
		Version:      server.Spec.Version,
		URL:          server.Spec.URL,
		DiscoveredAt: time.Now(),
		Meta: map[string]interface{}{
			"source":         "mcpserver-cr",
			"sourceRegistry": server.Status.SourceRegistry,
		},
	}
	if out.Name == "" {
		out.Name = server.Name
	}
	if server.Spec.Repository != nil {
		out.Repository = models.Repository{
			URL:    server.Spec.Repository.URL,
			Source: server.Spec.Repository.Source,
		}
	}
	for _, p := range server.Spec.Packages {
		out.Packages = append(out.Packages, models.Package{
			RegistryType: p.RegistryType,
			Identifier:   p.Identifier,
			Transport:    models.Transport{Type: p.Transport.Type},
		})
	}
	return out
}

func (r *MCPServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.MCPServer{}).
		Named("mcpserver").
		Complete(r)
}
