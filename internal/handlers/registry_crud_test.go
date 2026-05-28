/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4g CR write-path unit tests for RegistryHandler. The handler talks
// to a fake controller-runtime client (no API server), so these test
// the projection / polling / coexistence-guard / priority logic in
// isolation. Reconciler behavior is simulated by mutating Status on the
// fake client when the test wants the poll loop to observe Ready.
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

	"github.com/gin-gonic/gin"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

const registryTestNamespace = "test-ns"

func newRegistryCRHandler(t *testing.T, objs ...client.Object) (*RegistryHandler, client.Client, MCPServerStore) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.MCPServer{}).
		Build()
	store := clients.NewInMemoryMCPServerStore()
	h := &RegistryHandler{
		Store:     store,
		crClient:  c,
		namespace: registryTestNamespace,
	}
	return h, c, store
}

// flipMCPServerReady marks Ready=True on the named MCPServer so a poll
// loop running concurrently observes the transition. Mirrors
// MCPServerReconciler's markActive call.
func flipMCPServerReady(t *testing.T, c client.Client, name string) {
	t.Helper()
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get mcpserver %s: %v", name, err)
	}
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.MCPServerConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Active",
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on %s: %v", name, err)
	}
}

func newRegistryGinContext(method, path string, body []byte, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	if body != nil {
		c.Request = httptest.NewRequest(method, path, bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
	} else {
		c.Request = httptest.NewRequest(method, path, nil)
	}
	c.Params = params
	return c, rec
}

// TestUploadRegistryEntry_CRPath_HappyPath: POST → CR create →
// reconciler flips Ready → poll returns "active" → 201 with default
// priority stamped on Status.Priority.
func TestUploadRegistryEntry_CRPath_HappyPath(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)

	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{
			ID:          "smoke-server",
			Name:        "Smoke Server",
			Description: "P2.4g smoke",
			Image:       "docker.io/library/echo:latest",
			Packages: []models.Package{
				{RegistryType: "oci", Identifier: "docker.io/library/echo:latest", Transport: models.Transport{Type: "stdio"}},
			},
		},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload", body, nil)
	ctx.Request.Header.Set("X-User-ID", "alice")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.MCPServer
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "smoke-server"}, &cr); err == nil {
				flipMCPServerReady(t, c, "smoke-server")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.UploadRegistryEntry(ctx)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp models.MCPServer
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if got := resp.Meta[mcpServerStatusMetaKey]; got != "active" {
		t.Errorf("_meta._status = %v, want active", got)
	}

	// CR has expected spec + default priority.
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "smoke-server"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Spec.DisplayName != "Smoke Server" {
		t.Errorf("DisplayName = %q, want Smoke Server", cr.Spec.DisplayName)
	}
	if cr.Status.Priority != defaultMCPServerPriority {
		t.Errorf("Status.Priority = %d, want %d", cr.Status.Priority, defaultMCPServerPriority)
	}
	if got := cr.Annotations[mcpServerAnnotationCreatedBy]; got != "alice" {
		t.Errorf("createdBy = %q, want alice", got)
	}
}

// TestUploadRegistryEntry_CRPath_ExplicitPriority: explicit priority in
// the request becomes the CR's Status.Priority.
func TestUploadRegistryEntry_CRPath_ExplicitPriority(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)
	pri := int32(500)
	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{ID: "pri-server", Name: "Pri Server"},
		Priority:  &pri,
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload", body, nil)
	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	ctx.Request = ctx.Request.WithContext(cctx)

	h.UploadRegistryEntry(ctx)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "pri-server"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Status.Priority != 500 {
		t.Errorf("Status.Priority = %d, want 500", cr.Status.Priority)
	}
}

// TestUploadRegistryEntry_CRPath_InvalidPriority: out-of-range priority
// → 400 before any CR is created.
func TestUploadRegistryEntry_CRPath_InvalidPriority(t *testing.T) {
	for _, tc := range []struct {
		name string
		pri  int32
	}{
		{"below_min", -1},
		{"above_max", 1001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c, _ := newRegistryCRHandler(t)
			p := tc.pri
			body, _ := json.Marshal(UploadRegistryEntryRequest{
				MCPServer: models.MCPServer{ID: "bad-pri", Name: "Bad"},
				Priority:  &p,
			})
			ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload", body, nil)
			h.UploadRegistryEntry(ctx)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			// CR must not have been created.
			var cr mcpv1alpha1.MCPServer
			err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "bad-pri"}, &cr)
			if err == nil || !apierrors.IsNotFound(err) {
				t.Errorf("expected NotFound for CR, got err=%v", err)
			}
		})
	}
}

// TestUploadRegistryEntry_CRPath_AlreadyExists: re-upload same id → 409.
func TestUploadRegistryEntry_CRPath_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: registryTestNamespace},
	}
	h, _, _ := newRegistryCRHandler(t, existing)

	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{ID: "dup", Name: "Dup"},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload", body, nil)
	h.UploadRegistryEntry(ctx)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestUploadRegistryEntry_CRPath_PollTimeout: no Ready flip → 201 with
// _meta._status="provisioning".
func TestUploadRegistryEntry_CRPath_PollTimeout(t *testing.T) {
	h, _, _ := newRegistryCRHandler(t)

	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{ID: "slow-server", Name: "Slow"},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload", body, nil)
	ctx.Request = ctx.Request.WithContext(cctx)

	h.UploadRegistryEntry(ctx)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp models.MCPServer
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := resp.Meta[mcpServerStatusMetaKey]; got != "provisioning" {
		t.Errorf("_meta._status = %v, want provisioning", got)
	}
}

// TestUpdateMCPServer_CRPath_HappyPath: PUT mutates Spec, OwnerReferences
// preserved, 200.
func TestUpdateMCPServer_CRPath_HappyPath(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "upd-server",
			Namespace: registryTestNamespace,
		},
		Spec: mcpv1alpha1.MCPServerSpec{DisplayName: "Old Name"},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{
			ID:          "upd-server",
			Name:        "New Name",
			Description: "updated",
		},
	})
	ctx, rec := newRegistryGinContext(http.MethodPut, "/api/v1/registry/upd-server", body, gin.Params{{Key: "id", Value: "upd-server"}})
	ctx.Request = ctx.Request.WithContext(cctx)

	h.UpdateMCPServer(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "upd-server"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Spec.DisplayName != "New Name" {
		t.Errorf("DisplayName = %q, want New Name", cr.Spec.DisplayName)
	}
	if cr.Spec.Description != "updated" {
		t.Errorf("Description = %q, want updated", cr.Spec.Description)
	}
}

// TestUpdateMCPServer_CRPath_OwnedByRegistry: 409 when the CR is owned
// by an MCPRegistry — and the message names that registry.
func TestUpdateMCPServer_CRPath_OwnedByRegistry(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owned-server",
			Namespace: registryTestNamespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "mcp.suse.com/v1alpha1",
				Kind:       mcpRegistryKind,
				Name:       "main-registry",
				UID:        "abc-123",
			}},
		},
		Spec: mcpv1alpha1.MCPServerSpec{DisplayName: "Locked"},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{ID: "owned-server", Name: "Try Edit"},
	})
	ctx, rec := newRegistryGinContext(http.MethodPut, "/api/v1/registry/owned-server", body, gin.Params{{Key: "id", Value: "owned-server"}})

	h.UpdateMCPServer(ctx)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "main-registry") {
		t.Errorf("body should name owning registry; got %s", rec.Body.String())
	}
	// CR Spec must be unchanged.
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "owned-server"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Spec.DisplayName != "Locked" {
		t.Errorf("DisplayName mutated to %q; should still be Locked", cr.Spec.DisplayName)
	}
}

// TestUpdateMCPServer_CRPath_PriorityChange: priority field rewrites
// Status.Priority via Status().Patch.
func TestUpdateMCPServer_CRPath_PriorityChange(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "pri-upd", Namespace: registryTestNamespace},
		Spec:       mcpv1alpha1.MCPServerSpec{DisplayName: "Old"},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	newPri := int32(750)
	body, _ := json.Marshal(UploadRegistryEntryRequest{
		MCPServer: models.MCPServer{ID: "pri-upd", Name: "Old"},
		Priority:  &newPri,
	})
	ctx, rec := newRegistryGinContext(http.MethodPut, "/api/v1/registry/pri-upd", body, gin.Params{{Key: "id", Value: "pri-upd"}})
	ctx.Request = ctx.Request.WithContext(cctx)

	h.UpdateMCPServer(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "pri-upd"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Status.Priority != 750 {
		t.Errorf("Status.Priority = %d, want 750", cr.Status.Priority)
	}
}

// TestDeleteMCPServer_CRPath_HappyPath: DELETE removes the CR → 204.
func TestDeleteMCPServer_CRPath_HappyPath(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "del-server", Namespace: registryTestNamespace},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	ctx, _ := newRegistryGinContext(http.MethodDelete, "/api/v1/registry/del-server", nil, gin.Params{{Key: "id", Value: "del-server"}})

	h.DeleteMCPServer(ctx)

	if got := ctx.Writer.Status(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", got)
	}
	var cr mcpv1alpha1.MCPServer
	err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "del-server"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got err=%v", err)
	}
}

// TestDeleteMCPServer_CRPath_OwnedByRegistry: 409, CR preserved.
func TestDeleteMCPServer_CRPath_OwnedByRegistry(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owned-del",
			Namespace: registryTestNamespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "mcp.suse.com/v1alpha1",
				Kind:       mcpRegistryKind,
				Name:       "main-registry",
				UID:        "abc-123",
			}},
		},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	ctx, rec := newRegistryGinContext(http.MethodDelete, "/api/v1/registry/owned-del", nil, gin.Params{{Key: "id", Value: "owned-del"}})

	h.DeleteMCPServer(ctx)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	// CR must still exist.
	var cr mcpv1alpha1.MCPServer
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: "owned-del"}, &cr); err != nil {
		t.Errorf("CR should still exist; got err=%v", err)
	}
}

// TestDeleteMCPServer_CRPath_NotFound: DELETE on missing CR → 404.
func TestDeleteMCPServer_CRPath_NotFound(t *testing.T) {
	h, _, _ := newRegistryCRHandler(t)
	ctx, rec := newRegistryGinContext(http.MethodDelete, "/api/v1/registry/ghost", nil, gin.Params{{Key: "id", Value: "ghost"}})

	h.DeleteMCPServer(ctx)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestIsOwnedByMCPRegistry recognizes MCPRegistry owner refs and ignores
// other kinds.
func TestIsOwnedByMCPRegistry(t *testing.T) {
	cases := []struct {
		name      string
		refs      []metav1.OwnerReference
		wantOwned bool
		wantName  string
	}{
		{"no refs", nil, false, ""},
		{"deployment ref only", []metav1.OwnerReference{{Kind: "Deployment", Name: "d"}}, false, ""},
		{"registry ref", []metav1.OwnerReference{{Kind: mcpRegistryKind, Name: "reg-a"}}, true, "reg-a"},
		{"mixed refs", []metav1.OwnerReference{
			{Kind: "ConfigMap", Name: "c"},
			{Kind: mcpRegistryKind, Name: "reg-b"},
		}, true, "reg-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cr := &mcpv1alpha1.MCPServer{ObjectMeta: metav1.ObjectMeta{OwnerReferences: tc.refs}}
			gotName, gotOwned := isOwnedByMCPRegistry(cr)
			if gotOwned != tc.wantOwned || gotName != tc.wantName {
				t.Errorf("got (%q, %v); want (%q, %v)", gotName, gotOwned, tc.wantName, tc.wantOwned)
			}
		})
	}
}

func bytesContains(b []byte, sub string) bool {
	return bytes.Contains(b, []byte(sub))
}

// ----------------------------------------------------------------------
// P2.4h: bulk upload CR-path tests
// ----------------------------------------------------------------------

func ptrInt32(v int32) *int32 { return &v }

// listAllMCPServers fetches every MCPServer in the test namespace via
// the fake client. Tests assert presence/absence by counting and by
// matching names, so a slice is enough.
func listAllMCPServers(t *testing.T, c client.Client) []mcpv1alpha1.MCPServer {
	t.Helper()
	var list mcpv1alpha1.MCPServerList
	if err := c.List(context.Background(), &list, client.InNamespace(registryTestNamespace)); err != nil {
		t.Fatalf("list mcpservers: %v", err)
	}
	return list.Items
}

// TestUploadBulkRegistryEntries_CRPath_HappyPath: 3 entries with mixed
// priorities → 201 count=3, all CRs created, Status.Priority stamped.
func TestUploadBulkRegistryEntries_CRPath_HappyPath(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "bulk-a", Name: "Bulk A"}},
		{MCPServer: models.MCPServer{ID: "bulk-b", Name: "Bulk B"}, Priority: ptrInt32(50)},
		{MCPServer: models.MCPServer{ID: "bulk-c", Name: "Bulk C"}, Priority: ptrInt32(750)},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)
	ctx.Request.Header.Set("X-User-ID", "alice")

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if count, _ := resp["count"].(float64); int(count) != 3 {
		t.Errorf("count = %v, want 3", resp["count"])
	}

	wantPri := map[string]int32{"bulk-a": defaultMCPServerPriority, "bulk-b": 50, "bulk-c": 750}
	for name, want := range wantPri {
		var cr mcpv1alpha1.MCPServer
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: registryTestNamespace, Name: name}, &cr); err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if cr.Status.Priority != want {
			t.Errorf("%s Status.Priority = %d, want %d", name, cr.Status.Priority, want)
		}
		if got := cr.Annotations[mcpServerAnnotationCreatedBy]; got != "alice" {
			t.Errorf("%s createdBy = %q, want alice", name, got)
		}
	}
}

// TestUploadBulkRegistryEntries_CRPath_InvalidPriority: bad priority on
// entry [1] → 400 with "index 1"; zero CRs created (fail-fast before
// any side effects).
func TestUploadBulkRegistryEntries_CRPath_InvalidPriority(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "ok-a", Name: "OK A"}},
		{MCPServer: models.MCPServer{ID: "bad-pri", Name: "Bad Pri"}, Priority: ptrInt32(9999)},
		{MCPServer: models.MCPServer{ID: "ok-c", Name: "OK C"}},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "index 1") {
		t.Errorf("body should name offending index; got %s", rec.Body.String())
	}
	if got := len(listAllMCPServers(t, c)); got != 0 {
		t.Errorf("CRs created on validation failure = %d, want 0", got)
	}
}

// TestUploadBulkRegistryEntries_CRPath_EmptyName: missing name on entry
// [2] → 400 with index, zero CRs created.
func TestUploadBulkRegistryEntries_CRPath_EmptyName(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "ok-a", Name: "OK A"}},
		{MCPServer: models.MCPServer{ID: "ok-b", Name: "OK B"}},
		{MCPServer: models.MCPServer{ID: "no-name"}}, // missing name
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "index 2") {
		t.Errorf("body should name offending index; got %s", rec.Body.String())
	}
	if got := len(listAllMCPServers(t, c)); got != 0 {
		t.Errorf("CRs created on validation failure = %d, want 0", got)
	}
}

// TestUploadBulkRegistryEntries_CRPath_DuplicateIDs: two entries share
// an ID → 400, zero CRs created.
func TestUploadBulkRegistryEntries_CRPath_DuplicateIDs(t *testing.T) {
	h, c, _ := newRegistryCRHandler(t)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "same", Name: "A"}},
		{MCPServer: models.MCPServer{ID: "other", Name: "B"}},
		{MCPServer: models.MCPServer{ID: "same", Name: "C"}},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "duplicate id") {
		t.Errorf("body should mention duplicate id; got %s", rec.Body.String())
	}
	if got := len(listAllMCPServers(t, c)); got != 0 {
		t.Errorf("CRs created on validation failure = %d, want 0", got)
	}
}

// TestUploadBulkRegistryEntries_CRPath_AlreadyExistsRollback: pre-create
// "dup-id"; bulk request [a, dup-id, c] → 409, only dup-id remains
// (a was rolled back; c never created).
func TestUploadBulkRegistryEntries_CRPath_AlreadyExistsRollback(t *testing.T) {
	existing := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "dup-id", Namespace: registryTestNamespace},
		Spec:       mcpv1alpha1.MCPServerSpec{DisplayName: "Pre-existing"},
	}
	h, c, _ := newRegistryCRHandler(t, existing)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "bulk-a", Name: "Bulk A"}},
		{MCPServer: models.MCPServer{ID: "dup-id", Name: "Conflict"}},
		{MCPServer: models.MCPServer{ID: "bulk-c", Name: "Bulk C"}},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "dup-id") {
		t.Errorf("body should name offending id; got %s", rec.Body.String())
	}
	if !bytesContains(rec.Body.Bytes(), "rolled back") {
		t.Errorf("body should mention rollback; got %s", rec.Body.String())
	}

	items := listAllMCPServers(t, c)
	if len(items) != 1 {
		t.Fatalf("MCPServers after rollback = %d, want 1; got %+v", len(items), itemNames(items))
	}
	if items[0].Name != "dup-id" {
		t.Errorf("surviving CR = %q, want dup-id", items[0].Name)
	}
	// Pre-existing CR's Spec untouched (we didn't mutate it).
	if items[0].Spec.DisplayName != "Pre-existing" {
		t.Errorf("pre-existing Spec mutated; DisplayName=%q", items[0].Spec.DisplayName)
	}
}

// TestUploadBulkRegistryEntries_CRPath_PriorityPatchFailureRollback:
// wrap the fake client so Status().Patch fails on the second call →
// first entry's CR rolled back, request fails.
func TestUploadBulkRegistryEntries_CRPath_PriorityPatchFailureRollback(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	base := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&mcpv1alpha1.MCPServer{}).
		Build()

	failing := &statusPatchFailingClient{Client: base, failAfter: 1}
	h := &RegistryHandler{
		Store:     clients.NewInMemoryMCPServerStore(),
		crClient:  failing,
		namespace: registryTestNamespace,
	}

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "first", Name: "First"}},
		{MCPServer: models.MCPServer{ID: "second", Name: "Second"}},
	})
	ctx, rec := newRegistryGinContext(http.MethodPost, "/api/v1/registry/upload/bulk", body, nil)

	h.UploadBulkRegistryEntries(ctx)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	// Both Created CRs should have been rolled back (Delete called).
	items := listAllMCPServers(t, base)
	if len(items) != 0 {
		t.Errorf("CRs after rollback = %d, want 0; got %+v", len(items), itemNames(items))
	}
}

// TestUploadBulkRegistryEntries_LegacyPath_AcceptsWrapperShape: the
// P2.4g wrapper shape (with optional `priority`) must decode harmlessly
// in legacy mode (no crClient). Priority is silently ignored — it has
// no meaning on the in-memory store.
func TestUploadBulkRegistryEntries_LegacyPath_AcceptsWrapperShape(t *testing.T) {
	rm := &fakeRegistryManager{}
	h, _ := newRegistryHandlerForTest(rm)
	router := gin.New()
	router.POST("/registry/upload/bulk", h.UploadBulkRegistryEntries)

	body, _ := json.Marshal([]UploadRegistryEntryRequest{
		{MCPServer: models.MCPServer{ID: "a", Name: "A"}, Priority: ptrInt32(500)},
		{MCPServer: models.MCPServer{ID: "b", Name: "B"}},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registry/upload/bulk", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(rm.uploadedEntries) != 2 {
		t.Fatalf("want 2 uploaded, got %d", len(rm.uploadedEntries))
	}
}

func itemNames(items []mcpv1alpha1.MCPServer) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Name
	}
	return out
}

// statusPatchFailingClient wraps a fake client and forces Status().Patch
// to return a non-conflict error on the Nth call (1-indexed via failAfter:
// the first failAfter calls succeed, subsequent calls fail). Lets the
// rollback test simulate a mid-bulk priority-patch failure.
type statusPatchFailingClient struct {
	client.Client
	failAfter int
	patchN    int
}

func (s *statusPatchFailingClient) Status() client.SubResourceWriter {
	return &statusPatchFailingWriter{parent: s, inner: s.Client.Status()}
}

type statusPatchFailingWriter struct {
	parent *statusPatchFailingClient
	inner  client.SubResourceWriter
}

func (w *statusPatchFailingWriter) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	return w.inner.Create(ctx, obj, subResource, opts...)
}

func (w *statusPatchFailingWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	return w.inner.Update(ctx, obj, opts...)
}

func (w *statusPatchFailingWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	w.parent.patchN++
	if w.parent.patchN > w.parent.failAfter {
		return apierrors.NewInternalError(errPatchInjected)
	}
	return w.inner.Patch(ctx, obj, patch, opts...)
}

var errPatchInjected = &injectedError{msg: "injected status patch failure"}

type injectedError struct{ msg string }

func (e *injectedError) Error() string { return e.msg }
