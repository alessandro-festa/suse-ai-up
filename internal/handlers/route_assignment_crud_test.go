/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4i CR write-path unit tests. Mirrors adapters_crud_test.go: the
// handler talks to a fake controller-runtime client and we assert on
// resulting CR state. The legacy tests in route_assignment_test.go
// exercise the in-process registryStore fallback (h.crClient == nil)
// and stay untouched.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
)

const routeAssignmentTestNamespace = "test-ns"

// newRouteCRTestHandler builds a RouteAssignmentHandler wired against a
// fake controller-runtime client plus an in-memory UserGroupService. The
// service is needed because the public HTTP methods run permission +
// ID-validation checks before branching to the CR helpers. Seeding a
// dev-admin caller via X-User-ID short-circuits CanManageGroups so the
// branch is reachable.
func newRouteCRTestHandler(t *testing.T, objs ...client.Object) (*RouteAssignmentHandler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.RouteAssignment{}).
		Build()

	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)

	h := NewRouteAssignmentHandler(svc, nil).WithCRClient(c, routeAssignmentTestNamespace)
	return h, c
}

// mcpServerObj returns a minimal MCPServer CR usable as a target for
// route assignment scoping.
func mcpServerObj(name string) *mcpv1alpha1.MCPServer {
	return &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: routeAssignmentTestNamespace},
	}
}

// --- CreateRouteAssignment CR path ----------------------------------------------

func TestCreateRouteAssignmentCR_HappyPath(t *testing.T) {
	h, c := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	body, _ := json.Marshal(CreateRouteAssignmentRequest{
		Permissions: "read",
		AutoSpawn:   true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/srv1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp models.RouteAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ServerID != "srv1" || resp.Permissions != "read" || !resp.AutoSpawn {
		t.Errorf("unexpected response: %+v", resp)
	}

	var list mcpv1alpha1.RouteAssignmentList
	if err := c.List(context.Background(), &list, client.InNamespace(routeAssignmentTestNamespace)); err != nil {
		t.Fatalf("list CRs: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want 1 CR, got %d", len(list.Items))
	}
	cr := list.Items[0]
	if cr.Spec.MCPServerRef == nil || cr.Spec.MCPServerRef.Name != "srv1" {
		t.Errorf("Spec.MCPServerRef = %+v, want {Name: srv1}", cr.Spec.MCPServerRef)
	}
	if cr.Spec.Permissions != mcpv1alpha1.RouteAssignmentPermissionRead {
		t.Errorf("Spec.Permissions = %q, want read", cr.Spec.Permissions)
	}
	if got := cr.Annotations[routeAssignmentAnnotationCreatedBy]; got != "dev-admin" {
		t.Errorf("createdBy annotation = %q, want dev-admin", got)
	}
}

func TestCreateRouteAssignmentCR_ServerNotFound(t *testing.T) {
	h, _ := newRouteCRTestHandler(t) // no MCPServer CRs seeded

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "read"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/missing/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateRouteAssignmentCR_InvalidPermissions(t *testing.T) {
	h, _ := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "superuser"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/srv1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestCreateRouteAssignmentCR_PermissionDenied(t *testing.T) {
	h, _ := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "read"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/srv1/routes", bytes.NewReader(body))
	// X-User-ID omitted → "default-user" lacks group:manage and is not dev-admin.
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// --- ListRouteAssignments CR path ----------------------------------------------

func TestListRouteAssignmentsCR_HappyPath(t *testing.T) {
	h, c := newRouteCRTestHandler(t, mcpServerObj("srv1"), mcpServerObj("srv2"))
	ctx := context.Background()

	// Seed assignments on both servers; the response must only carry srv1's.
	for _, ra := range []*mcpv1alpha1.RouteAssignment{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a-srv1", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv1"},
				Permissions:  mcpv1alpha1.RouteAssignmentPermissionRead,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a-srv2", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv2"},
				Permissions:  mcpv1alpha1.RouteAssignmentPermissionAdmin,
			},
		},
	} {
		if err := c.Create(ctx, ra); err != nil {
			t.Fatalf("seed CR: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/srv1/routes", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var got []models.RouteAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a-srv1" || got[0].ServerID != "srv1" {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestListRouteAssignmentsCR_EmptyServerExists(t *testing.T) {
	h, _ := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/srv1/routes", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var got []models.RouteAssignment
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 0 {
		t.Errorf("want empty list, got %+v", got)
	}
}

func TestListRouteAssignmentsCR_ServerNotFound(t *testing.T) {
	h, _ := newRouteCRTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/missing/routes", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

// --- UpdateRouteAssignment CR path ----------------------------------------------

func TestUpdateRouteAssignmentCR_HappyPath(t *testing.T) {
	h, c := newRouteCRTestHandler(t,
		mcpServerObj("srv1"),
		&mcpv1alpha1.RouteAssignment{
			ObjectMeta: metav1.ObjectMeta{Name: "a1", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv1"},
				Permissions:  mcpv1alpha1.RouteAssignmentPermissionRead,
			},
		},
	)

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write", AutoSpawn: true})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/srv1/routes/a1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var got mcpv1alpha1.RouteAssignment
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: routeAssignmentTestNamespace, Name: "a1"}, &got); err != nil {
		t.Fatalf("get updated CR: %v", err)
	}
	if got.Spec.Permissions != mcpv1alpha1.RouteAssignmentPermissionWrite {
		t.Errorf("Permissions = %q, want write", got.Spec.Permissions)
	}
	if !got.Spec.AutoSpawn {
		t.Errorf("AutoSpawn = false, want true")
	}
}

func TestUpdateRouteAssignmentCR_CrossServerIsolation(t *testing.T) {
	h, _ := newRouteCRTestHandler(t,
		mcpServerObj("srv1"),
		mcpServerObj("srv2"),
		&mcpv1alpha1.RouteAssignment{
			ObjectMeta: metav1.ObjectMeta{Name: "a1", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv1"},
				Permissions:  mcpv1alpha1.RouteAssignmentPermissionRead,
			},
		},
	)

	// Attempt to update a1 under srv2's path → 404 to avoid leaking a CR
	// that belongs to a different MCPServer.
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/srv2/routes/a1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateRouteAssignmentCR_AssignmentNotFound(t *testing.T) {
	h, _ := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/srv1/routes/missing", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

// --- DeleteRouteAssignment CR path ----------------------------------------------

func TestDeleteRouteAssignmentCR_HappyPath(t *testing.T) {
	h, c := newRouteCRTestHandler(t,
		mcpServerObj("srv1"),
		&mcpv1alpha1.RouteAssignment{
			ObjectMeta: metav1.ObjectMeta{Name: "a1", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv1"},
			},
		},
	)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/srv1/routes/a1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", rec.Code, rec.Body.String())
	}

	var got mcpv1alpha1.RouteAssignment
	err := c.Get(context.Background(), client.ObjectKey{Namespace: routeAssignmentTestNamespace, Name: "a1"}, &got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("post-delete Get error = %v, want IsNotFound", err)
	}
}

func TestDeleteRouteAssignmentCR_CrossServerIsolation(t *testing.T) {
	h, c := newRouteCRTestHandler(t,
		mcpServerObj("srv1"),
		mcpServerObj("srv2"),
		&mcpv1alpha1.RouteAssignment{
			ObjectMeta: metav1.ObjectMeta{Name: "a1", Namespace: routeAssignmentTestNamespace},
			Spec: mcpv1alpha1.RouteAssignmentSpec{
				MCPServerRef: &corev1.LocalObjectReference{Name: "srv1"},
			},
		},
	)

	// DELETE under srv2's path → 404 and the CR survives.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/srv2/routes/a1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}

	var got mcpv1alpha1.RouteAssignment
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: routeAssignmentTestNamespace, Name: "a1"}, &got); err != nil {
		t.Errorf("CR should still exist, got error: %v", err)
	}
}

func TestDeleteRouteAssignmentCR_PermissionDenied(t *testing.T) {
	h, _ := newRouteCRTestHandler(t, mcpServerObj("srv1"))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/srv1/routes/a1", nil)
	// no X-User-ID
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}
