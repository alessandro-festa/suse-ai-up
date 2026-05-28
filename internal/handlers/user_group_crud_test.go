/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4f unit tests for the CR-mode helpers in user_group_crud.go.
// The handler talks to a fake controller-runtime client (no API server),
// so we exercise the projection / Secret-pairing / poll-loop logic in
// isolation. Tests call createUserCR / updateUserCR / deleteUserCR
// directly to skip the userGroupService permission check (which is
// covered by the existing tests for those handlers).
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"golang.org/x/crypto/bcrypt"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

const userGroupTestNamespace = "test-ns"

func newUserGroupTestHandler(t *testing.T, objs ...client.Object) (*UserGroupHandler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.User{}, &mcpv1alpha1.Group{}).
		Build()
	h := &UserGroupHandler{
		crClient:  c,
		namespace: userGroupTestNamespace,
		// userGroupService intentionally nil — CR helpers must not touch it.
	}
	return h, c
}

// flipUserReady marks UserConditionReady=True so a concurrent poll loop
// observes the transition. Mirrors the UserReconciler's happy path.
func flipUserReady(t *testing.T, c client.Client, name string) {
	t.Helper()
	var cr mcpv1alpha1.User
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get user %s: %v", name, err)
	}
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.UserConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Active",
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on user %s: %v", name, err)
	}
}

// flipGroupReady marks GroupConditionReady=True so a concurrent poll loop
// observes the transition. Mirrors the GroupReconciler's empty-Members path.
func flipGroupReady(t *testing.T, c client.Client, name string) {
	t.Helper()
	var cr mcpv1alpha1.Group
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get group %s: %v", name, err)
	}
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.GroupConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on group %s: %v", name, err)
	}
}

func newRequest(method, path string, body []byte) (*httptest.ResponseRecorder, *http.Request) {
	rec := httptest.NewRecorder()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return rec, req
}

// TestCreateUserCR_HappyPath: User CR + Secret created, ownerRef
// stamped, poll observes Ready, 201 with status="active".
func TestCreateUserCR_HappyPath(t *testing.T) {
	h, c := newUserGroupTestHandler(t)

	req := &CreateUserRequest{
		ID:       "alice",
		Name:     "Alice Wonder",
		Email:    "alice@example.com",
		Password: "super-secret",
	}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var u mcpv1alpha1.User
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "alice"}, &u); err == nil {
				// Wait for PasswordSecretRef to land too, so we know the
				// handler has finished both Create and the patch Update.
				if u.Spec.PasswordSecretRef != nil {
					flipUserReady(t, c, "alice")
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.createUserCR(rec, httpReq, req)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp CreateUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "active" {
		t.Errorf("status = %q, want active", resp.Status)
	}
	if resp.User.ID != "alice" {
		t.Errorf("user.id = %q, want alice", resp.User.ID)
	}

	var cr mcpv1alpha1.User
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "alice"}, &cr); err != nil {
		t.Fatalf("get user CR: %v", err)
	}
	if cr.Spec.PasswordSecretRef == nil {
		t.Fatalf("PasswordSecretRef nil after create")
	}
	if cr.Spec.PasswordSecretRef.Name != "user-alice-password" {
		t.Errorf("PasswordSecretRef.Name = %q", cr.Spec.PasswordSecretRef.Name)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "user-alice-password"}, &secret); err != nil {
		t.Fatalf("get password secret: %v", err)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Name != "alice" {
		t.Errorf("OwnerReferences = %+v, want single ref to alice", secret.OwnerReferences)
	}
	if err := bcrypt.CompareHashAndPassword(secret.Data["password"], []byte("super-secret")); err != nil {
		t.Errorf("bcrypt mismatch: %v", err)
	}
}

// TestCreateUserCR_PollTimeout: no Ready flip → 201 with
// status="provisioning". Uses a short request context so the poll loop
// exits via ctx.Done.
func TestCreateUserCR_PollTimeout(t *testing.T) {
	h, _ := newUserGroupTestHandler(t)
	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := &CreateUserRequest{
		ID:       "slow",
		Name:     "Slow",
		Email:    "slow@example.com",
		Password: "long-enough-pw",
	}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)
	httpReq = httpReq.WithContext(cctx)

	h.createUserCR(rec, httpReq, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	var resp CreateUserResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "provisioning" {
		t.Errorf("status = %q, want provisioning", resp.Status)
	}
}

// TestCreateUserCR_AlreadyExists: re-Create same ID → 409.
func TestCreateUserCR_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: userGroupTestNamespace},
	}
	h, _ := newUserGroupTestHandler(t, existing)

	req := &CreateUserRequest{ID: "dup", Name: "Dup", Email: "d@x"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)

	h.createUserCR(rec, httpReq, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestCreateUserCR_NoPassword: omitting Password creates the CR but no
// Secret; the User's PasswordSecretRef stays nil. Valid for users that
// will later set a password via Update (or federated users once that
// path lands).
func TestCreateUserCR_NoPassword(t *testing.T) {
	h, c := newUserGroupTestHandler(t)
	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := &CreateUserRequest{ID: "no-pw", Name: "NoPw", Email: "n@x"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)
	httpReq = httpReq.WithContext(cctx)

	h.createUserCR(rec, httpReq, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.User
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "no-pw"}, &cr); err != nil {
		t.Fatalf("get user CR: %v", err)
	}
	if cr.Spec.PasswordSecretRef != nil {
		t.Errorf("PasswordSecretRef = %+v, want nil", cr.Spec.PasswordSecretRef)
	}
	var secret corev1.Secret
	err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "user-no-pw-password"}, &secret)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected no Secret; err=%v", err)
	}
}

// TestCreateUserCR_PasswordTooShort: password below the 8-char floor →
// 400, no CR or Secret created.
func TestCreateUserCR_PasswordTooShort(t *testing.T) {
	h, c := newUserGroupTestHandler(t)
	req := &CreateUserRequest{ID: "short", Name: "S", Email: "s@x", Password: "abc"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)

	h.createUserCR(rec, httpReq, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var cr mcpv1alpha1.User
	err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "short"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected CR not created; err=%v", err)
	}
}

// TestCreateUserCR_FederatedProvider: github/rancher rejected with 400
// until the federated-login flow lands.
func TestCreateUserCR_FederatedProvider(t *testing.T) {
	h, _ := newUserGroupTestHandler(t)
	req := &CreateUserRequest{ID: "fed", Name: "F", Email: "f@x", AuthProvider: "github"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/users", body)

	h.createUserCR(rec, httpReq, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestUpdateUserCR_MetadataOnly: DisplayName / Email / Groups round-trip
// while PasswordSecretRef and AuthProvider survive the in-place mutate.
func TestUpdateUserCR_MetadataOnly(t *testing.T) {
	existing := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: userGroupTestNamespace},
		Spec: mcpv1alpha1.UserSpec{
			DisplayName:  "Old Name",
			Email:        "old@x",
			AuthProvider: mcpv1alpha1.UserAuthProviderLocal,
			PasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "user-alice-password"},
				Key:                  "password",
			},
		},
	}
	h, c := newUserGroupTestHandler(t, existing)

	req := &UpdateUserRequest{Name: "New Name", Email: "new@x", Groups: []string{"team-a"}}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPut, "/api/v1/users/alice", body)

	h.updateUserCR(rec, httpReq, "alice", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.User
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "alice"}, &cr); err != nil {
		t.Fatalf("get user CR: %v", err)
	}
	if cr.Spec.DisplayName != "New Name" {
		t.Errorf("DisplayName = %q", cr.Spec.DisplayName)
	}
	if cr.Spec.Email != "new@x" {
		t.Errorf("Email = %q", cr.Spec.Email)
	}
	if len(cr.Spec.Groups) != 1 || cr.Spec.Groups[0].Name != "team-a" {
		t.Errorf("Groups = %+v", cr.Spec.Groups)
	}
	if cr.Spec.PasswordSecretRef == nil || cr.Spec.PasswordSecretRef.Name != "user-alice-password" {
		t.Errorf("PasswordSecretRef wiped by metadata-only update: %+v", cr.Spec.PasswordSecretRef)
	}
	if cr.Spec.AuthProvider != mcpv1alpha1.UserAuthProviderLocal {
		t.Errorf("AuthProvider = %q, want local", cr.Spec.AuthProvider)
	}
}

// TestUpdateUserCR_RotatePassword: existing Secret is updated in place,
// new bcrypt hash matches the new password, old hash no longer matches.
func TestUpdateUserCR_RotatePassword(t *testing.T) {
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	existing := []client.Object{
		&mcpv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: userGroupTestNamespace},
			Spec: mcpv1alpha1.UserSpec{
				AuthProvider: mcpv1alpha1.UserAuthProviderLocal,
				PasswordSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "user-alice-password"},
					Key:                  "password",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "user-alice-password", Namespace: userGroupTestNamespace},
			Data:       map[string][]byte{"password": oldHash},
		},
	}
	h, c := newUserGroupTestHandler(t, existing...)

	req := &UpdateUserRequest{Password: "new-password"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPut, "/api/v1/users/alice", body)

	h.updateUserCR(rec, httpReq, "alice", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "user-alice-password"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(secret.Data["password"], []byte("new-password")); err != nil {
		t.Errorf("new password not stored: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(secret.Data["password"], []byte("old-password")); err == nil {
		t.Errorf("old password still matches after rotation")
	}
}

// TestUpdateUserCR_SetInitialPassword: a User with no PasswordSecretRef
// gets one created on first Update with a Password, including ownerRef
// and the patched Spec.
func TestUpdateUserCR_SetInitialPassword(t *testing.T) {
	existing := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: userGroupTestNamespace},
		Spec:       mcpv1alpha1.UserSpec{AuthProvider: mcpv1alpha1.UserAuthProviderLocal},
	}
	h, c := newUserGroupTestHandler(t, existing)

	req := &UpdateUserRequest{Password: "brand-new-pw"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPut, "/api/v1/users/alice", body)

	h.updateUserCR(rec, httpReq, "alice", req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.User
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "alice"}, &cr); err != nil {
		t.Fatalf("get user CR: %v", err)
	}
	if cr.Spec.PasswordSecretRef == nil {
		t.Fatalf("PasswordSecretRef still nil after Update with Password")
	}
	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "user-alice-password"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].Name != "alice" {
		t.Errorf("OwnerReferences = %+v", secret.OwnerReferences)
	}
}

// TestDeleteUserCR_AndIdempotent: delete returns 204, the CR is gone,
// re-delete returns 404.
func TestDeleteUserCR_AndIdempotent(t *testing.T) {
	existing := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: userGroupTestNamespace},
	}
	h, c := newUserGroupTestHandler(t, existing)

	rec, httpReq := newRequest(http.MethodDelete, "/api/v1/users/alice", nil)
	h.deleteUserCR(rec, httpReq, "alice")

	if rec.Code != http.StatusNoContent {
		t.Fatalf("first delete = %d, want 204", rec.Code)
	}
	var cr mcpv1alpha1.User
	err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "alice"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete; err=%v", err)
	}

	rec2, httpReq2 := newRequest(http.MethodDelete, "/api/v1/users/alice", nil)
	h.deleteUserCR(rec2, httpReq2, "alice")
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", rec2.Code)
	}
}

// TestCreateGroupCR_HappyPath: Group CR created, poll observes Ready
// (empty Members → immediate Ready in the reconciler), 201 with
// status="ready".
func TestCreateGroupCR_HappyPath(t *testing.T) {
	h, c := newUserGroupTestHandler(t)

	req := &CreateGroupRequest{ID: "team-a", Name: "Team A", Permissions: []string{"server:read"}}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/groups", body)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var g mcpv1alpha1.Group
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "team-a"}, &g); err == nil {
				flipGroupReady(t, c, "team-a")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.createGroupCR(rec, httpReq, req)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp CreateGroupResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "ready" {
		t.Errorf("status = %q, want ready", resp.Status)
	}
	if resp.Group.ID != "team-a" || resp.Group.Name != "Team A" {
		t.Errorf("group = %+v", resp.Group)
	}
}

// TestCreateGroupCR_AlreadyExists: re-Create same ID → 409.
func TestCreateGroupCR_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: userGroupTestNamespace},
	}
	h, _ := newUserGroupTestHandler(t, existing)

	req := &CreateGroupRequest{ID: "dup", Name: "Dup"}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPost, "/api/v1/groups", body)

	h.createGroupCR(rec, httpReq, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// TestUpdateGroupCR: DisplayName / Description / Permissions round-trip,
// Members unaffected.
func TestUpdateGroupCR(t *testing.T) {
	existing := &mcpv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a", Namespace: userGroupTestNamespace},
		Spec: mcpv1alpha1.GroupSpec{
			DisplayName: "Old",
			Members:     []corev1.LocalObjectReference{{Name: "alice"}},
		},
	}
	h, c := newUserGroupTestHandler(t, existing)

	req := &UpdateGroupRequest{Name: "New", Description: "desc", Permissions: []string{"adapter:create"}}
	body, _ := json.Marshal(req)
	rec, httpReq := newRequest(http.MethodPut, "/api/v1/groups/team-a", body)

	h.updateGroupCR(rec, httpReq, "team-a", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.Group
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: userGroupTestNamespace, Name: "team-a"}, &cr)
	if cr.Spec.DisplayName != "New" || cr.Spec.Description != "desc" {
		t.Errorf("spec = %+v", cr.Spec)
	}
	if len(cr.Spec.Permissions) != 1 || cr.Spec.Permissions[0] != "adapter:create" {
		t.Errorf("Permissions = %+v", cr.Spec.Permissions)
	}
	if len(cr.Spec.Members) != 1 || cr.Spec.Members[0].Name != "alice" {
		t.Errorf("Members wiped by update: %+v", cr.Spec.Members)
	}
}

// TestDeleteGroupCR_AndIdempotent: delete returns 204, re-delete 404.
func TestDeleteGroupCR_AndIdempotent(t *testing.T) {
	existing := &mcpv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a", Namespace: userGroupTestNamespace},
	}
	h, _ := newUserGroupTestHandler(t, existing)

	rec, httpReq := newRequest(http.MethodDelete, "/api/v1/groups/team-a", nil)
	h.deleteGroupCR(rec, httpReq, "team-a")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first delete = %d, want 204", rec.Code)
	}

	rec2, httpReq2 := newRequest(http.MethodDelete, "/api/v1/groups/team-a", nil)
	h.deleteGroupCR(rec2, httpReq2, "team-a")
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", rec2.Code)
	}
}

// TestCreateUserResponse_HasStatusField guards the additive DTO change —
// accidentally removing the field would break callers polling on
// "provisioning". Same guard exists for plugin in plugin_crud_test.go.
func TestCreateUserResponse_HasStatusField(t *testing.T) {
	resp := CreateUserResponse{Status: "active"}
	b, _ := json.Marshal(resp)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["status"]; !ok {
		t.Errorf("CreateUserResponse JSON missing \"status\": %s", string(b))
	}
}

// TestCreateGroupResponse_HasStatusField guards the additive DTO change.
func TestCreateGroupResponse_HasStatusField(t *testing.T) {
	resp := CreateGroupResponse{Status: "ready"}
	b, _ := json.Marshal(resp)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["status"]; !ok {
		t.Errorf("CreateGroupResponse JSON missing \"status\": %s", string(b))
	}
}
