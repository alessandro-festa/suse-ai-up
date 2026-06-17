/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// VirtualMCPRoute CRUD handler unit tests. Same shape as
// agents_crud_test.go — fake controller-runtime client, no API server.
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/services"
)

func newVRouteCRUDTestHandler(t *testing.T, objs ...client.Object) (*VirtualMCPRouteHandler, client.Client) {
	t.Helper()
	scheme := newTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.VirtualMCPRoute{}).
		Build()

	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)

	h := &VirtualMCPRouteHandler{
		crClient:         c,
		namespace:        testNamespace,
		userGroupService: svc,
	}
	return h, c
}

func flipVRouteReady(t *testing.T, c client.Client, name string, status metav1.ConditionStatus, reason string, entries []mcpv1alpha1.ResolvedEntry) {
	t.Helper()
	var cr mcpv1alpha1.VirtualMCPRoute
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get vroute %s: %v", name, err)
	}
	cr.Status.Phase = mcpv1alpha1.VirtualMCPRoutePhaseReady
	cr.Status.ResolvedEntries = entries
	cr.Status.EntryCount = int32(len(entries))
	now := metav1.Now()
	cr.Status.LastResolvedTime = &now
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.VirtualMCPRouteConditionReady,
		Status:             status,
		Reason:             reason,
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on %s: %v", name, err)
	}
}

func TestCreateVirtualMCPRoute_HappyPath(t *testing.T) {
	h, c := newVRouteCRUDTestHandler(t)

	body, _ := json.Marshal(CreateVirtualMCPRouteRequest{
		Name:      "ops-route",
		ExposedAs: "ops-route",
		Sources: []VirtualMCPSourceDTO{
			{
				AdapterName: "weather-adapter",
				Tools:       &VirtualMCPSelectorDTO{All: true},
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vroutes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.VirtualMCPRoute
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ops-route"}, &cr); err == nil {
				flipVRouteReady(t, c, "ops-route", metav1.ConditionTrue, "Ready", []mcpv1alpha1.ResolvedEntry{
					{Name: "weather", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "weather-adapter"},
				})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateVirtualMCPRoute(rec, req)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp VirtualMCPRouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Status != vrouteStatusReady {
		t.Errorf("status = %q, want %q", resp.Status, vrouteStatusReady)
	}
	if resp.EntryCount != 1 || len(resp.ResolvedEntries) != 1 {
		t.Errorf("entryCount=%d resolved=%d, want 1 entry projected in create response", resp.EntryCount, len(resp.ResolvedEntries))
	}
	if len(resp.Sources) != 1 || resp.Sources[0].AdapterName != "weather-adapter" || !resp.Sources[0].Tools.All {
		t.Errorf("sources = %+v, want one adapter source with tools.all", resp.Sources)
	}

	var cr mcpv1alpha1.VirtualMCPRoute
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "ops-route"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if got := cr.Annotations[vrouteAnnotationCreatedBy]; got != "dev-admin" {
		t.Errorf("createdBy = %q, want dev-admin", got)
	}
}

func TestCreateVirtualMCPRoute_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		req  CreateVirtualMCPRouteRequest
		want string
	}{
		{"missing name", CreateVirtualMCPRouteRequest{
			Sources: []VirtualMCPSourceDTO{{AdapterName: "a"}},
		}, "name is required"},
		{"no sources", CreateVirtualMCPRouteRequest{
			Name: "r",
		}, "at least one entry"},
		{"source with both refs", CreateVirtualMCPRouteRequest{
			Name:    "r",
			Sources: []VirtualMCPSourceDTO{{AdapterName: "a", MCPServerName: "s"}},
		}, "exactly one of adapterName or mcpServerName"},
		{"source with neither ref", CreateVirtualMCPRouteRequest{
			Name:    "r",
			Sources: []VirtualMCPSourceDTO{{}},
		}, "exactly one of adapterName or mcpServerName"},
		{"selector with two modes", CreateVirtualMCPRouteRequest{
			Name: "r",
			Sources: []VirtualMCPSourceDTO{{
				AdapterName: "a",
				Tools:       &VirtualMCPSelectorDTO{All: true, Prefix: "x-"},
			}},
		}, "at most one of all/names/prefix/regex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newVRouteCRUDTestHandler(t)
			body, _ := json.Marshal(tc.req)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/vroutes", bytes.NewReader(body))
			req.Header.Set("X-User-ID", "dev-admin")
			rec := httptest.NewRecorder()
			h.CreateVirtualMCPRoute(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
				t.Errorf("body=%s does not contain %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestCreateVirtualMCPRoute_Forbidden(t *testing.T) {
	h, _ := newVRouteCRUDTestHandler(t)
	body, _ := json.Marshal(CreateVirtualMCPRouteRequest{
		Name:    "r",
		Sources: []VirtualMCPSourceDTO{{AdapterName: "a"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vroutes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "alice")
	rec := httptest.NewRecorder()
	h.CreateVirtualMCPRoute(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestListVsGet_ResolvedEntriesOmitted — list-vs-get toggle for
// resolvedEntries. List omits it (payload size); get includes it.
func TestListVsGet_ResolvedEntriesOmitted(t *testing.T) {
	existing := &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-x", Namespace: testNamespace},
		Spec: mcpv1alpha1.VirtualMCPRouteSpec{
			Sources: []mcpv1alpha1.VirtualMCPSource{{
				AdapterRef: &corev1.LocalObjectReference{Name: "a"},
				Tools:      &mcpv1alpha1.VirtualMCPSelector{All: true},
			}},
		},
	}
	h, c := newVRouteCRUDTestHandler(t, existing)
	flipVRouteReady(t, c, "route-x", metav1.ConditionTrue, "Ready", []mcpv1alpha1.ResolvedEntry{
		{Name: "t1", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "a"},
		{Name: "t2", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "a"},
	})

	// List
	listRec := httptest.NewRecorder()
	h.ListVirtualMCPRoutes(listRec, httptest.NewRequest(http.MethodGet, "/api/v1/vroutes", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listRec.Code)
	}
	var list []VirtualMCPRouteResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list length = %d, want 1", len(list))
	}
	if list[0].EntryCount != 2 {
		t.Errorf("list entryCount = %d, want 2", list[0].EntryCount)
	}
	if len(list[0].ResolvedEntries) != 0 {
		t.Errorf("list ResolvedEntries should be omitted; got %+v", list[0].ResolvedEntries)
	}

	// Get
	getRec := httptest.NewRecorder()
	h.GetVirtualMCPRoute(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/vroutes/route-x", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", getRec.Code)
	}
	var got VirtualMCPRouteResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.EntryCount != 2 || len(got.ResolvedEntries) != 2 {
		t.Errorf("get entryCount=%d resolved=%d, want 2/2", got.EntryCount, len(got.ResolvedEntries))
	}
	if got.LastResolvedAt == nil {
		t.Errorf("get LastResolvedAt is nil, want populated")
	}
}

func TestUpdateVirtualMCPRoute_ReplacesSources(t *testing.T) {
	existing := &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-y", Namespace: testNamespace},
		Spec: mcpv1alpha1.VirtualMCPRouteSpec{
			Sources: []mcpv1alpha1.VirtualMCPSource{{
				AdapterRef: &corev1.LocalObjectReference{Name: "old"},
				Tools:      &mcpv1alpha1.VirtualMCPSelector{All: true},
			}},
		},
	}
	h, c := newVRouteCRUDTestHandler(t, existing)

	body, _ := json.Marshal(UpdateVirtualMCPRouteRequest{
		Description: "updated",
		Sources: []VirtualMCPSourceDTO{
			{AdapterName: "new", Tools: &VirtualMCPSelectorDTO{Names: []string{"only-this"}}},
		},
		ACL: []string{"assignment-1"},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/vroutes/route-y", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateVirtualMCPRoute(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.VirtualMCPRoute
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "route-y"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if len(cr.Spec.Sources) != 1 || cr.Spec.Sources[0].AdapterRef == nil || cr.Spec.Sources[0].AdapterRef.Name != "new" {
		t.Errorf("Sources = %+v, want [{AdapterRef:new}]", cr.Spec.Sources)
	}
	if cr.Spec.Sources[0].Tools == nil || len(cr.Spec.Sources[0].Tools.Names) != 1 || cr.Spec.Sources[0].Tools.Names[0] != "only-this" {
		t.Errorf("Tools selector = %+v, want Names=[only-this]", cr.Spec.Sources[0].Tools)
	}
	if len(cr.Spec.ACL) != 1 || cr.Spec.ACL[0].Name != "assignment-1" {
		t.Errorf("ACL = %+v, want [assignment-1]", cr.Spec.ACL)
	}
}

func TestDeleteVirtualMCPRoute(t *testing.T) {
	existing := &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "todelete", Namespace: testNamespace},
		Spec: mcpv1alpha1.VirtualMCPRouteSpec{
			Sources: []mcpv1alpha1.VirtualMCPSource{{AdapterRef: &corev1.LocalObjectReference{Name: "a"}}},
		},
	}
	h, c := newVRouteCRUDTestHandler(t, existing)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/vroutes/todelete", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteVirtualMCPRoute(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	var cr mcpv1alpha1.VirtualMCPRoute
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "todelete"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got err=%v", err)
	}
}

func TestGetVirtualMCPRoute_NotFound(t *testing.T) {
	h, _ := newVRouteCRUDTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vroutes/missing", nil)
	rec := httptest.NewRecorder()
	h.GetVirtualMCPRoute(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestVRouteNameFromPath(t *testing.T) {
	cases := map[string]string{
		"/api/v1/vroutes/foo":         "foo",
		"/api/v1/vroutes/foo/mcp":     "foo",
		"/api/v1/vroutes/":            "",
		"/api/v1/agents/foo":          "",
	}
	for in, want := range cases {
		if got := vrouteNameFromPath(in); got != want {
			t.Errorf("vrouteNameFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTerminalVRouteReason(t *testing.T) {
	cases := map[string]bool{
		"SourceMissing": true,
		"Conflict":      true,
		"InvalidSpec":   true,
		"Resolving":     false,
		"":              false,
	}
	for reason, want := range cases {
		if got := isTerminalVRouteReason(reason); got != want {
			t.Errorf("isTerminalVRouteReason(%q) = %v, want %v", reason, got, want)
		}
	}
}
