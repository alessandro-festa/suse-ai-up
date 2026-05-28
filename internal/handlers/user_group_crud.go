/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4f CR-backed write path for /api/v1/users and /api/v1/groups.
// Mirrors the layout of adapters_crud.go / plugin_crud.go: the legacy
// handlers in users.go and groups.go branch here on h.crClient != nil,
// and these helpers project the HTTP DTOs onto User / Group CRs, create
// (and for users, plant a paired password Secret), then poll
// Status.Conditions[Ready] so the response stays synchronous for the
// common case. Reconciler is the source of truth for the auth
// projection; this file only writes CRs.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/auth"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// Same ~5s synchronous budget the adapter path uses. The reconciler runs
// in-process so most flips happen within tens of ms; the budget exists for
// validateGroups / validatePasswordSecret edge cases.
const (
	userGroupPollInterval = 100 * time.Millisecond
	userGroupPollTimeout  = 5 * time.Second

	// passwordSecretKey is the data key the User CR's PasswordSecretRef
	// always points at. Fixed to keep handler ↔ reconciler in lockstep —
	// the reconciler validates ref.Key, so handler-side variation would
	// be a configuration footgun for no benefit.
	passwordSecretKey = "password"

	// passwordMinLength is enforced only when a Password is supplied.
	// Empty Password is permitted (the User CR is then created without a
	// PasswordSecretRef and the reconciler tolerates that for local users
	// — see user_controller.validatePasswordSecret).
	passwordMinLength = 8
)

// passwordSecretName returns the deterministic Secret name paired with a
// User CR. Deterministic so Update can locate it without a label scan,
// and so a stale Secret left by a prior failed Create surfaces clearly
// as a 409.
func passwordSecretName(userID string) string {
	return fmt.Sprintf("user-%s-password", userID)
}

// createUserCR materializes a User CR (and optional password Secret)
// from a CreateUserRequest. Ordering matters: the User is created first
// so the Secret can carry an ownerReference to it (Kubernetes GC then
// cascades deletes). The User Spec.PasswordSecretRef is patched after
// the Secret exists.
func (h *UserGroupHandler) createUserCR(w http.ResponseWriter, r *http.Request, req *CreateUserRequest) {
	ctx := r.Context()

	provider := req.AuthProvider
	if provider == "" {
		provider = string(mcpv1alpha1.UserAuthProviderLocal)
	}
	// Federated providers (github/rancher) need a different create
	// flow (no Secret, ExternalID populated from the OAuth callback).
	// Rejecting here keeps the door open for that follow-up without
	// half-implementing it now.
	if provider != string(mcpv1alpha1.UserAuthProviderLocal) {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("authProvider %q is not yet supported by the HTTP create path; only %q is implemented", provider, mcpv1alpha1.UserAuthProviderLocal),
		})
		return
	}

	if req.Password != "" && len(req.Password) < passwordMinLength {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("password must be at least %d characters", passwordMinLength),
		})
		return
	}

	user := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.ID,
			Namespace: h.namespace,
		},
		Spec: mcpv1alpha1.UserSpec{
			DisplayName:  req.Name,
			Email:        req.Email,
			AuthProvider: mcpv1alpha1.UserAuthProvider(provider),
			Groups:       toLocalObjectRefs(req.Groups),
		},
	}

	if err := h.crClient.Create(ctx, user); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("User %q already exists", req.ID)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create User CR: " + err.Error()})
		return
	}

	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			// Hash failure is a programming error from bcrypt's POV; roll
			// back the User CR rather than leaving it in a half-state.
			_ = h.crClient.Delete(ctx, user)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to hash password: " + err.Error()})
			return
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      passwordSecretName(req.ID),
				Namespace: h.namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{passwordSecretKey: []byte(hash)},
		}
		if err := controllerutil.SetControllerReference(user, secret, h.crClient.Scheme()); err != nil {
			_ = h.crClient.Delete(ctx, user)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to set owner ref on password secret: " + err.Error()})
			return
		}
		if err := h.crClient.Create(ctx, secret); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// A stale Secret from a prior failed create remains and
				// we deliberately do NOT auto-update: rewriting it would
				// let a re-POST silently overwrite credentials that an
				// operator might trust. Surface a 409 and require the
				// caller to clean up the stale Secret.
				_ = h.crClient.Delete(ctx, user)
				writeJSON(w, http.StatusConflict, ErrorResponse{
					Error: fmt.Sprintf("stale password secret %q remains for user %q; remove it and retry", secret.Name, req.ID),
				})
				return
			}
			_ = h.crClient.Delete(ctx, user)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create password secret: " + err.Error()})
			return
		}

		// Patch the User CR with PasswordSecretRef now that the Secret
		// exists. Separate Update because we needed the User UID for the
		// ownerReference. The reconciler tolerates the brief window
		// between Create and this Update (validatePasswordSecret skips
		// when PasswordSecretRef is nil).
		//
		// Re-fetch + retry on conflict: between Create and here the
		// reconciler runs (in-process) and bumps ResourceVersion when it
		// flips Status.Conditions / adds a finalizer. The cached `user`
		// from Create is therefore stale by the time we Update.
		ref := &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name},
			Key:                  passwordSecretKey,
		}
		if err := h.setPasswordSecretRefWithRetry(ctx, req.ID, ref); err != nil {
			_ = h.crClient.Delete(ctx, user)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to patch User with PasswordSecretRef: " + err.Error()})
			return
		}
	}

	observed, readyStatus := h.pollUserReady(ctx, req.ID)

	response := CreateUserResponse{
		User:      userCRToModel(observed),
		CreatedAt: time.Now().UTC(),
		Status:    readyStatus,
	}
	writeJSON(w, http.StatusCreated, response)
}

// updateUserCR mutates the User CR in place from an UpdateUserRequest.
// Mirrors updateAdapterCR's mutate-in-place pattern so Spec fields not
// touched by the request (PasswordSecretRef, AuthProvider, ExternalID,
// ProviderGroups) survive the round-trip.
func (h *UserGroupHandler) updateUserCR(w http.ResponseWriter, r *http.Request, userID string, req *UpdateUserRequest) {
	ctx := r.Context()

	var user mcpv1alpha1.User
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: userID}, &user); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "User not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch User CR: " + err.Error()})
		return
	}

	if req.Name != "" {
		user.Spec.DisplayName = req.Name
	}
	if req.Email != "" {
		user.Spec.Email = req.Email
	}
	if req.Groups != nil {
		user.Spec.Groups = toLocalObjectRefs(req.Groups)
	}

	if req.Password != "" {
		if len(req.Password) < passwordMinLength {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: fmt.Sprintf("password must be at least %d characters", passwordMinLength),
			})
			return
		}
		if err := h.upsertPasswordSecret(ctx, &user, req.Password); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update password secret: " + err.Error()})
			return
		}
	}

	if err := h.crClient.Update(ctx, &user); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "User was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update User CR: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, userCRToModel(&user))
}

// deleteUserCR removes the User CR. The paired password Secret is
// removed by Kubernetes GC via the ownerReference stamped at Create —
// no manual delete needed, which sidesteps the "Secret outlives User"
// race that haunted earlier iterations.
func (h *UserGroupHandler) deleteUserCR(w http.ResponseWriter, r *http.Request, userID string) {
	cr := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userID,
			Namespace: h.namespace,
		},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "User not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete User CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setPasswordSecretRefWithRetry patches the User CR's Spec.PasswordSecretRef.
// Re-fetches before each Update so a stale ResourceVersion (the
// reconciler runs in-process and bumps RV via Status/finalizer updates
// the moment after Create) doesn't cause spurious 409s. Bounded retries
// (3 attempts) keep the failure mode predictable; conflicts past that
// indicate something pathological.
func (h *UserGroupHandler) setPasswordSecretRefWithRetry(ctx context.Context, userID string, ref *corev1.SecretKeySelector) error {
	const maxAttempts = 3
	var lastErr error
	for range maxAttempts {
		var fresh mcpv1alpha1.User
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: userID}, &fresh); err != nil {
			return fmt.Errorf("refetch user: %w", err)
		}
		fresh.Spec.PasswordSecretRef = ref
		err := h.crClient.Update(ctx, &fresh)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("update user after %d attempts: %w", maxAttempts, lastErr)
}

// upsertPasswordSecret either updates the existing Secret's hash or
// creates a fresh one (handles the "User was created without a password,
// now setting one" case). When it creates, it also patches the User's
// PasswordSecretRef in memory — caller's subsequent Update flushes the
// new ref.
func (h *UserGroupHandler) upsertPasswordSecret(ctx context.Context, user *mcpv1alpha1.User, plaintext string) error {
	hash, err := auth.HashPassword(plaintext)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	secretName := passwordSecretName(user.Name)
	if user.Spec.PasswordSecretRef != nil && user.Spec.PasswordSecretRef.Name != "" {
		secretName = user.Spec.PasswordSecretRef.Name
	}
	var sec corev1.Secret
	getErr := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: secretName}, &sec)
	switch {
	case getErr == nil:
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[passwordSecretKey] = []byte(hash)
		return h.crClient.Update(ctx, &sec)
	case apierrors.IsNotFound(getErr):
		fresh := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: h.namespace},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{passwordSecretKey: []byte(hash)},
		}
		if err := controllerutil.SetControllerReference(user, fresh, h.crClient.Scheme()); err != nil {
			return fmt.Errorf("owner ref: %w", err)
		}
		if err := h.crClient.Create(ctx, fresh); err != nil {
			return fmt.Errorf("create secret: %w", err)
		}
		user.Spec.PasswordSecretRef = &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
			Key:                  passwordSecretKey,
		}
		return nil
	default:
		return getErr
	}
}

// createGroupCR materializes a Group CR. Members are NOT accepted at
// create time — the User↔Group denormalization is one-way at HEAD and
// exposing Members in the create DTO would imply guarantees the
// reconciler doesn't enforce.
func (h *UserGroupHandler) createGroupCR(w http.ResponseWriter, r *http.Request, req *CreateGroupRequest) {
	ctx := r.Context()

	group := &mcpv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.ID,
			Namespace: h.namespace,
		},
		Spec: mcpv1alpha1.GroupSpec{
			DisplayName: req.Name,
			Description: req.Description,
			Permissions: append([]string(nil), req.Permissions...),
		},
	}

	if err := h.crClient.Create(ctx, group); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("Group %q already exists", req.ID)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create Group CR: " + err.Error()})
		return
	}

	observed, readyStatus := h.pollGroupReady(ctx, req.ID)

	response := CreateGroupResponse{
		Group:     groupCRToModel(observed),
		CreatedAt: time.Now().UTC(),
		Status:    readyStatus,
	}
	writeJSON(w, http.StatusCreated, response)
}

// updateGroupCR mutates the Group CR in place. Members are intentionally
// not touched — Group membership management is its own follow-up (needs
// a parent-patch design that keeps User.Spec.Groups consistent).
func (h *UserGroupHandler) updateGroupCR(w http.ResponseWriter, r *http.Request, groupID string, req *UpdateGroupRequest) {
	ctx := r.Context()

	var group mcpv1alpha1.Group
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: groupID}, &group); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Group not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Group CR: " + err.Error()})
		return
	}

	if req.Name != "" {
		group.Spec.DisplayName = req.Name
	}
	if req.Description != "" {
		group.Spec.Description = req.Description
	}
	if req.Permissions != nil {
		group.Spec.Permissions = append([]string(nil), req.Permissions...)
	}

	if err := h.crClient.Update(ctx, &group); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "Group was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update Group CR: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, groupCRToModel(&group))
}

// deleteGroupCR removes the Group CR. Members are not cleared on User
// CRs — Group.Spec.Members is the denormalized reverse edge and User
// CRs keep their forward Spec.Groups list intact (mirrors the existing
// model where deleting a group leaves user groups untouched).
func (h *UserGroupHandler) deleteGroupCR(w http.ResponseWriter, r *http.Request, groupID string) {
	cr := &mcpv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      groupID,
			Namespace: h.namespace,
		},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Group not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete Group CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pollUserReady waits up to userGroupPollTimeout for UserConditionReady
// to flip. "active" / "provisioning" mirror the legacy fileStore's "user
// exists immediately" semantics while keeping the failure mode visible.
func (h *UserGroupHandler) pollUserReady(ctx context.Context, name string) (*mcpv1alpha1.User, string) {
	deadline := time.Now().Add(userGroupPollTimeout)
	var latest mcpv1alpha1.User
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			for _, c := range latest.Status.Conditions {
				if c.Type == mcpv1alpha1.UserConditionReady && c.Status == metav1.ConditionTrue {
					return &latest, "active"
				}
			}
		}
		if time.Now().After(deadline) {
			return &latest, "provisioning"
		}
		select {
		case <-ctx.Done():
			return &latest, "provisioning"
		case <-time.After(userGroupPollInterval):
		}
	}
}

// pollGroupReady waits up to userGroupPollTimeout for GroupConditionReady
// to flip. With no Members in the create DTO, this is almost always
// immediate on the first poll.
func (h *UserGroupHandler) pollGroupReady(ctx context.Context, name string) (*mcpv1alpha1.Group, string) {
	deadline := time.Now().Add(userGroupPollTimeout)
	var latest mcpv1alpha1.Group
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			for _, c := range latest.Status.Conditions {
				if c.Type == mcpv1alpha1.GroupConditionReady && c.Status == metav1.ConditionTrue {
					return &latest, "ready"
				}
			}
		}
		if time.Now().After(deadline) {
			return &latest, "provisioning"
		}
		select {
		case <-ctx.Done():
			return &latest, "provisioning"
		case <-time.After(userGroupPollInterval):
		}
	}
}

// toLocalObjectRefs translates a list of bare names into the
// LocalObjectReference shape Spec.Groups / Spec.Members use.
func toLocalObjectRefs(names []string) []corev1.LocalObjectReference {
	if len(names) == 0 {
		return nil
	}
	out := make([]corev1.LocalObjectReference, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		out = append(out, corev1.LocalObjectReference{Name: n})
	}
	return out
}

// userCRToModel projects a User CR onto the HTTP models.User shape.
// PasswordHash stays zero (it's marshaled as "-" anyway) and timestamps
// come from ObjectMeta.CreationTimestamp; LastLoginAt is sourced from
// Status (reconciler-set when login flows update it).
func userCRToModel(u *mcpv1alpha1.User) models.User {
	if u == nil {
		return models.User{}
	}
	groups := make([]string, 0, len(u.Spec.Groups))
	for _, ref := range u.Spec.Groups {
		if ref.Name != "" {
			groups = append(groups, ref.Name)
		}
	}
	displayName := u.Spec.DisplayName
	if displayName == "" {
		displayName = u.Name
	}
	m := models.User{
		ID:             u.Name,
		Name:           displayName,
		Email:          u.Spec.Email,
		Groups:         groups,
		AuthProvider:   string(u.Spec.AuthProvider),
		ExternalID:     u.Spec.ExternalID,
		ProviderGroups: append([]string(nil), u.Spec.ProviderGroups...),
		CreatedAt:      u.CreationTimestamp.Time,
		UpdatedAt:      u.CreationTimestamp.Time,
	}
	if u.Status.LastLoginTime != nil {
		t := u.Status.LastLoginTime.Time
		m.LastLoginAt = &t
	}
	if u.Status.PasswordChangedTime != nil {
		t := u.Status.PasswordChangedTime.Time
		m.PasswordChangedAt = &t
	}
	return m
}

// groupCRToModel projects a Group CR onto models.Group.
func groupCRToModel(g *mcpv1alpha1.Group) models.Group {
	if g == nil {
		return models.Group{}
	}
	members := make([]string, 0, len(g.Spec.Members))
	for _, ref := range g.Spec.Members {
		if ref.Name != "" {
			members = append(members, ref.Name)
		}
	}
	displayName := g.Spec.DisplayName
	if displayName == "" {
		displayName = g.Name
	}
	return models.Group{
		ID:          g.Name,
		Name:        displayName,
		Description: g.Spec.Description,
		Members:     members,
		Permissions: append([]string(nil), g.Spec.Permissions...),
		CreatedAt:   g.CreationTimestamp.Time,
		UpdatedAt:   g.CreationTimestamp.Time,
	}
}
