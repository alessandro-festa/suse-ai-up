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

	corev1 "k8s.io/api/core/v1"
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

// UserReconciler validates a User CR's group/secret references, sets
// Status, and reflects the projection into an in-process auth.UserStore
// the §2.4 HTTP shim consults at request time.
type UserReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Store is nil-tolerant: envtest paths can omit it.
	Store auth.UserStore
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=users,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=users/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=groups,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

// Reconcile validates Spec.Groups[] and Spec.PasswordSecretRef, sets
// Phase + Conditions, and reflects to the UserStore. Missing references
// degrade Phase to Pending (groups) or Failed (secret).
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	id := req.Namespace + "/" + req.Name

	var user mcpv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if apierrors.IsNotFound(err) {
			if r.Store != nil {
				_ = r.Store.DeleteUser(id)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching User: %w", err)
	}

	missingGroups, err := r.validateGroups(ctx, &user)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("validating groups: %w", err)
	}

	missingSecret, secretReason, err := r.validatePasswordSecret(ctx, &user)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("validating password secret: %w", err)
	}

	phase, ready, readyReason, readyMsg, groupsReason, groupsMsg, groupsStatus := computeUserPhase(missingGroups, missingSecret, secretReason)

	if _, err := r.patchUserStatus(ctx, &user, func(s *mcpv1alpha1.UserStatus) {
		s.Phase = phase
		s.ObservedGeneration = user.Generation
		setMetaCondition(&s.Conditions, user.Generation,
			mcpv1alpha1.UserConditionReady, ready, readyReason, readyMsg)
		setMetaCondition(&s.Conditions, user.Generation,
			mcpv1alpha1.UserConditionGroupsResolved, groupsStatus, groupsReason, groupsMsg)
	}); err != nil {
		return ctrl.Result{}, err
	}

	// Reflect to store: keep entries for everything except Failed; data
	// plane should not route a Failed user even if their other refs are
	// otherwise valid.
	if r.Store != nil {
		if phase == mcpv1alpha1.UserPhaseFailed {
			_ = r.Store.DeleteUser(id)
		} else {
			if err := r.Store.UpsertUser(toRegisteredUser(&user)); err != nil {
				logger.Error(err, "UserStore.UpsertUser", "id", id)
			}
		}
	}

	return ctrl.Result{}, nil
}

// validateGroups checks each Spec.Groups entry exists in-namespace.
// Returns the sorted list of missing group names.
func (r *UserReconciler) validateGroups(ctx context.Context, user *mcpv1alpha1.User) ([]string, error) {
	var missing []string
	for _, ref := range user.Spec.Groups {
		if ref.Name == "" {
			continue
		}
		var g mcpv1alpha1.Group
		err := r.Get(ctx, types.NamespacedName{Namespace: user.Namespace, Name: ref.Name}, &g)
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

// validatePasswordSecret checks that the referenced Secret exists and
// carries the declared key, but only for local-provider users. Returns
// (missing, reason, err) — reason is one of "SecretMissing" or "KeyMissing"
// for status messages.
func (r *UserReconciler) validatePasswordSecret(ctx context.Context, user *mcpv1alpha1.User) (bool, string, error) {
	if user.Spec.AuthProvider != mcpv1alpha1.UserAuthProviderLocal {
		return false, "", nil
	}
	ref := user.Spec.PasswordSecretRef
	if ref == nil || ref.Name == "" {
		return false, "", nil
	}
	var sec corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: user.Namespace, Name: ref.Name}, &sec)
	switch {
	case apierrors.IsNotFound(err):
		return true, "SecretMissing", nil
	case err != nil:
		return false, "", err
	}
	if ref.Key != "" {
		if _, ok := sec.Data[ref.Key]; !ok {
			return true, "KeyMissing", nil
		}
	}
	return false, "", nil
}

// computeUserPhase encodes the precedence: PasswordSecret failure
// dominates over Groups-Pending (a Failed user is broken regardless of
// group resolution); otherwise Groups-missing -> Pending; else Active.
func computeUserPhase(missingGroups []string, missingSecret bool, secretReason string) (
	phase mcpv1alpha1.UserPhase,
	ready metav1.ConditionStatus,
	readyReason, readyMsg string,
	groupsReason, groupsMsg string,
	groupsStatus metav1.ConditionStatus,
) {
	groupsStatus = metav1.ConditionTrue
	groupsReason = "AllGroupsResolved"
	groupsMsg = "All referenced groups exist in this namespace."
	if len(missingGroups) > 0 {
		groupsStatus = metav1.ConditionFalse
		groupsReason = "GroupsMissing"
		groupsMsg = fmt.Sprintf("Missing Group CR(s): %s", strings.Join(missingGroups, ", "))
	}

	switch {
	case missingSecret:
		phase = mcpv1alpha1.UserPhaseFailed
		ready = metav1.ConditionFalse
		readyReason = "PasswordSecretMissing"
		if secretReason == "KeyMissing" {
			readyMsg = "Spec.PasswordSecretRef references a Secret whose declared key is absent."
		} else {
			readyMsg = "Spec.PasswordSecretRef references a Secret that does not exist."
		}
	case len(missingGroups) > 0:
		phase = mcpv1alpha1.UserPhasePending
		ready = metav1.ConditionFalse
		readyReason = "GroupsMissing"
		readyMsg = groupsMsg
	default:
		phase = mcpv1alpha1.UserPhaseActive
		ready = metav1.ConditionTrue
		readyReason = "Active"
		readyMsg = "User is fully reconciled and active."
	}
	return
}

func (r *UserReconciler) patchUserStatus(ctx context.Context, user *mcpv1alpha1.User, mutate func(*mcpv1alpha1.UserStatus)) (ctrl.Result, error) {
	original := user.DeepCopy()
	mutate(&user.Status)
	if err := r.Status().Patch(ctx, user, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching User status: %w", err)
	}
	return ctrl.Result{}, nil
}

func toRegisteredUser(u *mcpv1alpha1.User) *auth.RegisteredUser {
	groups := make([]string, 0, len(u.Spec.Groups))
	for _, ref := range u.Spec.Groups {
		if ref.Name != "" {
			groups = append(groups, ref.Name)
		}
	}
	sort.Strings(groups)
	provider := u.Spec.AuthProvider
	if provider == "" {
		provider = mcpv1alpha1.UserAuthProviderLocal
	}
	return &auth.RegisteredUser{
		ID:           u.Namespace + "/" + u.Name,
		Namespace:    u.Namespace,
		Name:         u.Name,
		DisplayName:  u.Spec.DisplayName,
		Email:        u.Spec.Email,
		AuthProvider: provider,
		ExternalID:   u.Spec.ExternalID,
		Groups:       groups,
	}
}

// SetupWithManager registers the reconciler. Watches on Group and
// Secret enqueue users whose Spec depends on the changed object so
// status flips without manual reconciliation.
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.User{}).
		Watches(&mcpv1alpha1.Group{}, handler.EnqueueRequestsFromMapFunc(r.mapGroupToUsers)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.mapSecretToUsers)).
		Named("user").
		Complete(r)
}

func (r *UserReconciler) mapGroupToUsers(ctx context.Context, obj client.Object) []reconcile.Request {
	g, ok := obj.(*mcpv1alpha1.Group)
	if !ok {
		return nil
	}
	var users mcpv1alpha1.UserList
	if err := r.List(ctx, &users, client.InNamespace(g.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range users.Items {
		u := &users.Items[i]
		for _, ref := range u.Spec.Groups {
			if ref.Name == g.Name {
				out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
					Namespace: u.Namespace, Name: u.Name,
				}})
				break
			}
		}
	}
	return out
}

func (r *UserReconciler) mapSecretToUsers(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var users mcpv1alpha1.UserList
	if err := r.List(ctx, &users, client.InNamespace(sec.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range users.Items {
		u := &users.Items[i]
		ref := u.Spec.PasswordSecretRef
		if ref != nil && ref.Name == sec.Name {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: u.Namespace, Name: u.Name,
			}})
		}
	}
	return out
}
