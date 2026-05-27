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
	"sort"
	"strings"

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
	"github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// GroupReconciler validates a Group CR's member references, sets
// Status (MemberCount + Conditions), and reflects the projection into
// an in-process auth.GroupStore.
type GroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Store is nil-tolerant: envtest paths can omit it.
	Store auth.GroupStore
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=groups,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=groups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=groups/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=users,verbs=get;list;watch

func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	id := req.Namespace + "/" + req.Name

	var group mcpv1alpha1.Group
	if err := r.Get(ctx, req.NamespacedName, &group); err != nil {
		if apierrors.IsNotFound(err) {
			if r.Store != nil {
				_ = r.Store.DeleteGroup(id)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching Group: %w", err)
	}

	missingMembers, err := r.validateMembers(ctx, &group)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("validating members: %w", err)
	}
	resolvedCount := len(group.Spec.Members) - len(missingMembers)
	if resolvedCount < 0 {
		resolvedCount = 0
	}

	phase, ready, readyReason, readyMsg, membersStatus, membersReason, membersMsg := computeGroupPhase(missingMembers)

	if _, err := r.patchGroupStatus(ctx, &group, func(s *mcpv1alpha1.GroupStatus) {
		s.Phase = phase
		s.MemberCount = int32(resolvedCount)
		s.ObservedGeneration = group.Generation
		setMetaCondition(&s.Conditions, group.Generation,
			mcpv1alpha1.GroupConditionReady, ready, readyReason, readyMsg)
		setMetaCondition(&s.Conditions, group.Generation,
			mcpv1alpha1.GroupConditionMembersResolved, membersStatus, membersReason, membersMsg)
	}); err != nil {
		return ctrl.Result{}, err
	}

	if r.Store != nil {
		if phase == mcpv1alpha1.GroupPhaseFailed {
			_ = r.Store.DeleteGroup(id)
		} else {
			if err := r.Store.UpsertGroup(toRegisteredGroup(&group)); err != nil {
				logger.Error(err, "GroupStore.UpsertGroup", "id", id)
			}
		}
	}

	return ctrl.Result{}, nil
}

// validateMembers checks each Spec.Members entry exists in-namespace.
// Returns the sorted list of missing user names.
func (r *GroupReconciler) validateMembers(ctx context.Context, group *mcpv1alpha1.Group) ([]string, error) {
	var missing []string
	for _, ref := range group.Spec.Members {
		if ref.Name == "" {
			continue
		}
		var u mcpv1alpha1.User
		err := r.Get(ctx, types.NamespacedName{Namespace: group.Namespace, Name: ref.Name}, &u)
		switch {
		case apierrors.IsNotFound(err):
			missing = append(missing, ref.Name)
		case err != nil:
			return nil, err
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func computeGroupPhase(missingMembers []string) (
	phase mcpv1alpha1.GroupPhase,
	ready metav1.ConditionStatus,
	readyReason, readyMsg string,
	membersStatus metav1.ConditionStatus,
	membersReason, membersMsg string,
) {
	if len(missingMembers) > 0 {
		return mcpv1alpha1.GroupPhasePending,
			metav1.ConditionFalse, "MembersMissing", fmt.Sprintf("Missing User CR(s): %s", strings.Join(missingMembers, ", ")),
			metav1.ConditionFalse, "MembersMissing", fmt.Sprintf("Missing User CR(s): %s", strings.Join(missingMembers, ", "))
	}
	return mcpv1alpha1.GroupPhaseReady,
		metav1.ConditionTrue, "Ready", "All declared members exist in this namespace.",
		metav1.ConditionTrue, "AllMembersResolved", "All declared members exist in this namespace."
}

func (r *GroupReconciler) patchGroupStatus(ctx context.Context, group *mcpv1alpha1.Group, mutate func(*mcpv1alpha1.GroupStatus)) (ctrl.Result, error) {
	original := group.DeepCopy()
	mutate(&group.Status)
	if err := r.Status().Patch(ctx, group, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching Group status: %w", err)
	}
	return ctrl.Result{}, nil
}

func toRegisteredGroup(g *mcpv1alpha1.Group) *auth.RegisteredGroup {
	members := make([]string, 0, len(g.Spec.Members))
	for _, ref := range g.Spec.Members {
		if ref.Name != "" {
			members = append(members, ref.Name)
		}
	}
	sort.Strings(members)
	perms := make([]string, len(g.Spec.Permissions))
	copy(perms, g.Spec.Permissions)
	return &auth.RegisteredGroup{
		ID:          g.Namespace + "/" + g.Name,
		Namespace:   g.Namespace,
		Name:        g.Name,
		DisplayName: g.Spec.DisplayName,
		Members:     members,
		Permissions: perms,
	}
}

// SetupWithManager watches User so a User CR add/update/delete that
// alters group-membership resolution re-reconciles the affected groups.
func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.Group{}).
		Watches(&mcpv1alpha1.User{}, handler.EnqueueRequestsFromMapFunc(r.mapUserToGroups)).
		Named("group").
		Complete(r)
}

// mapUserToGroups enqueues groups affected by a User change:
//   - groups declared in user.Spec.Groups (forward edge), and
//   - groups whose Spec.Members references this user (reverse edge),
//
// since either side gates this group's MembersResolved condition.
func (r *GroupReconciler) mapUserToGroups(ctx context.Context, obj client.Object) []reconcile.Request {
	u, ok := obj.(*mcpv1alpha1.User)
	if !ok {
		return nil
	}
	var groups mcpv1alpha1.GroupList
	if err := r.List(ctx, &groups, client.InNamespace(u.Namespace)); err != nil {
		return nil
	}
	forward := make(map[string]bool, len(u.Spec.Groups))
	for _, ref := range u.Spec.Groups {
		forward[ref.Name] = true
	}
	var out []reconcile.Request
	for i := range groups.Items {
		g := &groups.Items[i]
		hit := forward[g.Name]
		if !hit {
			for _, ref := range g.Spec.Members {
				if ref.Name == u.Name {
					hit = true
					break
				}
			}
		}
		if hit {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: g.Namespace, Name: g.Name,
			}})
		}
	}
	return out
}
