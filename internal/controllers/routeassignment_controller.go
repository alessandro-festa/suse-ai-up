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

// RouteAssignmentReconciler validates a RouteAssignment's subject
// references, expands them via read-time union over the User↔Group
// edges, and detects whether any route resource references this
// assignment. Reflects the projection into auth.AssignmentStore.
type RouteAssignmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Store is nil-tolerant: envtest paths can omit it.
	Store auth.AssignmentStore
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=routeassignments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=routeassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=routeassignments/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=users,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=groups,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=adapters,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=virtualmcproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=agents,verbs=get;list;watch

func (r *RouteAssignmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	id := req.Namespace + "/" + req.Name

	var asg mcpv1alpha1.RouteAssignment
	if err := r.Get(ctx, req.NamespacedName, &asg); err != nil {
		if apierrors.IsNotFound(err) {
			if r.Store != nil {
				_ = r.Store.DeleteAssignment(id)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching RouteAssignment: %w", err)
	}

	missingSubjects, err := r.validateSubjects(ctx, &asg)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("validating subjects: %w", err)
	}

	resolvedCount, err := r.resolveSubjects(ctx, &asg)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolving subjects: %w", err)
	}

	referenced, err := r.isAssignmentReferenced(ctx, asg.Name, asg.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking route references: %w", err)
	}

	phase, ready, readyReason, readyMsg,
		subjectsStatus, subjectsReason, subjectsMsg,
		refStatus, refReason, refMsg := computeAssignmentPhase(missingSubjects, referenced)

	if _, err := r.patchAssignmentStatus(ctx, &asg, func(s *mcpv1alpha1.RouteAssignmentStatus) {
		s.Phase = phase
		s.ResolvedSubjectCount = int32(resolvedCount)
		s.ObservedGeneration = asg.Generation
		setMetaCondition(&s.Conditions, asg.Generation,
			mcpv1alpha1.RouteAssignmentConditionReady, ready, readyReason, readyMsg)
		setMetaCondition(&s.Conditions, asg.Generation,
			mcpv1alpha1.RouteAssignmentConditionSubjectsResolved, subjectsStatus, subjectsReason, subjectsMsg)
		setMetaCondition(&s.Conditions, asg.Generation,
			mcpv1alpha1.RouteAssignmentConditionReferencedByRoute, refStatus, refReason, refMsg)
	}); err != nil {
		return ctrl.Result{}, err
	}

	if r.Store != nil {
		if phase == mcpv1alpha1.RouteAssignmentPhaseFailed {
			_ = r.Store.DeleteAssignment(id)
		} else {
			if err := r.Store.UpsertAssignment(toRegisteredAssignment(&asg)); err != nil {
				logger.Error(err, "AssignmentStore.UpsertAssignment", "id", id)
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *RouteAssignmentReconciler) validateSubjects(ctx context.Context, asg *mcpv1alpha1.RouteAssignment) ([]string, error) {
	var missing []string
	for _, ref := range asg.Spec.Users {
		if ref.Name == "" {
			continue
		}
		var u mcpv1alpha1.User
		err := r.Get(ctx, types.NamespacedName{Namespace: asg.Namespace, Name: ref.Name}, &u)
		switch {
		case apierrors.IsNotFound(err):
			missing = append(missing, "user/"+ref.Name)
		case err != nil:
			return nil, err
		}
	}
	for _, ref := range asg.Spec.Groups {
		if ref.Name == "" {
			continue
		}
		var g mcpv1alpha1.Group
		err := r.Get(ctx, types.NamespacedName{Namespace: asg.Namespace, Name: ref.Name}, &g)
		switch {
		case apierrors.IsNotFound(err):
			missing = append(missing, "group/"+ref.Name)
		case err != nil:
			return nil, err
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// resolveSubjects expands the assignment's declared subjects via the
// read-time union: declared Users ∪ each declared Group's Members ∪
// Users whose Spec.Groups lists one of the declared groups. Missing
// users/groups are silently skipped here — they're already surfaced by
// validateSubjects as the SubjectsResolved condition.
func (r *RouteAssignmentReconciler) resolveSubjects(ctx context.Context, asg *mcpv1alpha1.RouteAssignment) (int, error) {
	set := make(map[string]struct{})
	for _, ref := range asg.Spec.Users {
		if ref.Name != "" {
			set[ref.Name] = struct{}{}
		}
	}

	groupNames := make(map[string]bool, len(asg.Spec.Groups))
	for _, ref := range asg.Spec.Groups {
		if ref.Name == "" {
			continue
		}
		groupNames[ref.Name] = true
		var g mcpv1alpha1.Group
		err := r.Get(ctx, types.NamespacedName{Namespace: asg.Namespace, Name: ref.Name}, &g)
		switch {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			return 0, err
		}
		for _, m := range g.Spec.Members {
			if m.Name != "" {
				set[m.Name] = struct{}{}
			}
		}
	}

	if len(groupNames) > 0 {
		var users mcpv1alpha1.UserList
		if err := r.List(ctx, &users, client.InNamespace(asg.Namespace)); err != nil {
			return 0, err
		}
		for i := range users.Items {
			u := &users.Items[i]
			for _, ref := range u.Spec.Groups {
				if groupNames[ref.Name] {
					set[u.Name] = struct{}{}
					break
				}
			}
		}
	}

	return len(set), nil
}

// isAssignmentReferenced returns true iff any Adapter
// (Spec.RouteAssignmentRefs), VirtualMCPRoute (Spec.ACL), or Agent
// (Spec.ACL) in the same namespace references this assignment by name.
func (r *RouteAssignmentReconciler) isAssignmentReferenced(ctx context.Context, name, namespace string) (bool, error) {
	var adapters mcpv1alpha1.AdapterList
	if err := r.List(ctx, &adapters, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for i := range adapters.Items {
		for _, ref := range adapters.Items[i].Spec.RouteAssignmentRefs {
			if ref.Name == name {
				return true, nil
			}
		}
	}

	var routes mcpv1alpha1.VirtualMCPRouteList
	if err := r.List(ctx, &routes, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for i := range routes.Items {
		for _, ref := range routes.Items[i].Spec.ACL {
			if ref.Name == name {
				return true, nil
			}
		}
	}

	var agents mcpv1alpha1.AgentList
	if err := r.List(ctx, &agents, client.InNamespace(namespace)); err != nil {
		return false, err
	}
	for i := range agents.Items {
		for _, ref := range agents.Items[i].Spec.ACL {
			if ref.Name == name {
				return true, nil
			}
		}
	}

	return false, nil
}

func computeAssignmentPhase(missingSubjects []string, referenced bool) (
	phase mcpv1alpha1.RouteAssignmentPhase,
	ready metav1.ConditionStatus, readyReason, readyMsg string,
	subjectsStatus metav1.ConditionStatus, subjectsReason, subjectsMsg string,
	refStatus metav1.ConditionStatus, refReason, refMsg string,
) {
	if len(missingSubjects) > 0 {
		phase = mcpv1alpha1.RouteAssignmentPhasePending
		msg := "Missing subject CR(s): " + strings.Join(missingSubjects, ", ")
		ready = metav1.ConditionFalse
		readyReason = "SubjectsMissing"
		readyMsg = msg
		subjectsStatus = metav1.ConditionFalse
		subjectsReason = "SubjectsMissing"
		subjectsMsg = msg
	} else {
		phase = mcpv1alpha1.RouteAssignmentPhaseReady
		ready = metav1.ConditionTrue
		readyReason = "Ready"
		readyMsg = "All declared subjects exist; assignment is enforceable."
		subjectsStatus = metav1.ConditionTrue
		subjectsReason = "AllSubjectsResolved"
		subjectsMsg = "All declared subjects exist in this namespace."
	}

	if referenced {
		refStatus = metav1.ConditionTrue
		refReason = "Referenced"
		refMsg = "At least one Adapter / VirtualMCPRoute / Agent references this assignment."
	} else {
		refStatus = metav1.ConditionFalse
		refReason = "Unreferenced"
		refMsg = "No Adapter / VirtualMCPRoute / Agent in this namespace references this assignment."
	}
	return
}

func (r *RouteAssignmentReconciler) patchAssignmentStatus(ctx context.Context, asg *mcpv1alpha1.RouteAssignment, mutate func(*mcpv1alpha1.RouteAssignmentStatus)) (ctrl.Result, error) {
	original := asg.DeepCopy()
	mutate(&asg.Status)
	if err := r.Status().Patch(ctx, asg, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching RouteAssignment status: %w", err)
	}
	return ctrl.Result{}, nil
}

func toRegisteredAssignment(a *mcpv1alpha1.RouteAssignment) *auth.RegisteredAssignment {
	users := make([]string, 0, len(a.Spec.Users))
	for _, ref := range a.Spec.Users {
		if ref.Name != "" {
			users = append(users, ref.Name)
		}
	}
	sort.Strings(users)
	groups := make([]string, 0, len(a.Spec.Groups))
	for _, ref := range a.Spec.Groups {
		if ref.Name != "" {
			groups = append(groups, ref.Name)
		}
	}
	sort.Strings(groups)
	perms := a.Spec.Permissions
	if perms == "" {
		perms = mcpv1alpha1.RouteAssignmentPermissionRead
	}
	var mcpServerRef string
	if a.Spec.MCPServerRef != nil {
		mcpServerRef = a.Spec.MCPServerRef.Name
	}
	return &auth.RegisteredAssignment{
		ID:           a.Namespace + "/" + a.Name,
		Namespace:    a.Namespace,
		Name:         a.Name,
		Users:        users,
		Groups:       groups,
		Permissions:  perms,
		AutoSpawn:    a.Spec.AutoSpawn,
		MCPServerRef: mcpServerRef,
	}
}

func (r *RouteAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.RouteAssignment{}).
		Watches(&mcpv1alpha1.User{}, handler.EnqueueRequestsFromMapFunc(r.mapUserToAssignments)).
		Watches(&mcpv1alpha1.Group{}, handler.EnqueueRequestsFromMapFunc(r.mapGroupToAssignments)).
		Watches(&mcpv1alpha1.Adapter{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteRefToAssignments)).
		Watches(&mcpv1alpha1.VirtualMCPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteRefToAssignments)).
		Watches(&mcpv1alpha1.Agent{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteRefToAssignments)).
		Named("routeassignment").
		Complete(r)
}

// mapUserToAssignments enqueues assignments affected by a User change:
// either the user is named directly, or the user lists a Group the
// assignment names (read-time union expands them as a subject).
func (r *RouteAssignmentReconciler) mapUserToAssignments(ctx context.Context, obj client.Object) []reconcile.Request {
	u, ok := obj.(*mcpv1alpha1.User)
	if !ok {
		return nil
	}
	var list mcpv1alpha1.RouteAssignmentList
	if err := r.List(ctx, &list, client.InNamespace(u.Namespace)); err != nil {
		return nil
	}
	userGroups := make(map[string]bool, len(u.Spec.Groups))
	for _, ref := range u.Spec.Groups {
		userGroups[ref.Name] = true
	}
	var out []reconcile.Request
	for i := range list.Items {
		a := &list.Items[i]
		hit := false
		for _, ref := range a.Spec.Users {
			if ref.Name == u.Name {
				hit = true
				break
			}
		}
		if !hit {
			for _, ref := range a.Spec.Groups {
				if userGroups[ref.Name] {
					hit = true
					break
				}
			}
		}
		if hit {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: a.Namespace, Name: a.Name,
			}})
		}
	}
	return out
}

func (r *RouteAssignmentReconciler) mapGroupToAssignments(ctx context.Context, obj client.Object) []reconcile.Request {
	g, ok := obj.(*mcpv1alpha1.Group)
	if !ok {
		return nil
	}
	var list mcpv1alpha1.RouteAssignmentList
	if err := r.List(ctx, &list, client.InNamespace(g.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		a := &list.Items[i]
		for _, ref := range a.Spec.Groups {
			if ref.Name == g.Name {
				out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
					Namespace: a.Namespace, Name: a.Name,
				}})
				break
			}
		}
	}
	return out
}

// mapRouteRefToAssignments enqueues every assignment named in an
// Adapter / VirtualMCPRoute / Agent's reference field. Used to flip the
// ReferencedByRoute condition when those CRs add/remove a reference.
func (r *RouteAssignmentReconciler) mapRouteRefToAssignments(ctx context.Context, obj client.Object) []reconcile.Request {
	var refs []corev1Like
	namespace := obj.GetNamespace()
	switch x := obj.(type) {
	case *mcpv1alpha1.Adapter:
		for _, ref := range x.Spec.RouteAssignmentRefs {
			refs = append(refs, corev1Like{Name: ref.Name})
		}
	case *mcpv1alpha1.VirtualMCPRoute:
		for _, ref := range x.Spec.ACL {
			refs = append(refs, corev1Like{Name: ref.Name})
		}
	case *mcpv1alpha1.Agent:
		for _, ref := range x.Spec.ACL {
			refs = append(refs, corev1Like{Name: ref.Name})
		}
	default:
		return nil
	}
	out := make([]reconcile.Request, 0, len(refs))
	for _, ref := range refs {
		if ref.Name == "" {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: namespace, Name: ref.Name,
		}})
	}
	return out
}

// corev1Like sidesteps importing corev1 here just to use
// LocalObjectReference; we only need the Name to enqueue.
type corev1Like struct{ Name string }
