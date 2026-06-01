/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5b VirtualMCPRouteHandler tests. The handler talks to a fake
// controller-runtime client seeded with VirtualMCPRoute CRs (Spec.ACL
// + Status.ResolvedEntries), and a stub MCPDispatcher that records
// dispatch calls and returns canned responses. Exercises:
//   - tools/list returns the projected catalog
//   - tools/call reverse-resolves + rewrites params.name + dispatches
//   - unknown tool name → JSON-RPC method-not-found
//   - MCPServer-source entry → JSON-RPC internal-error (out of scope)
//   - ACL: matched user passes; unmatched user → 403; empty ACL fail-open
//   - Route not found → 404
//   - Unsupported JSON-RPC method → JSON-RPC method-not-found
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

const vroutesTestNamespace = "test-ns"

// stubDispatcher records each ProxyMCPToAdapter call and returns a
// canned response. Lets the tests assert on the dispatched adapter +
// rewritten body without standing up a real upstream.
type stubDispatcher struct {
	mu     sync.Mutex
	calls  []dispatchCall
	respSC int
	respCT string
	respB  []byte
	respE  error
}

type dispatchCall struct {
	AdapterID string
	UserID    string
	Body      []byte
}

func (s *stubDispatcher) ProxyMCPToAdapter(ctx context.Context, adapterID, userID string, body []byte, headers http.Header) (int, string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, dispatchCall{AdapterID: adapterID, UserID: userID, Body: append([]byte(nil), body...)})
	return s.respSC, s.respCT, s.respB, s.respE
}

func (s *stubDispatcher) lastCall() dispatchCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return dispatchCall{}
	}
	return s.calls[len(s.calls)-1]
}

func newVRouteHandler(t *testing.T, objs ...client.Object) (*VirtualMCPRouteHandler, client.Client, *stubDispatcher, clients.UserStore) {
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
		WithStatusSubresource(&mcpv1alpha1.VirtualMCPRoute{}).
		Build()

	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	ugSvc := services.NewUserGroupService(userStore, groupStore)

	dispatcher := &stubDispatcher{
		respSC: http.StatusOK,
		respCT: "application/json",
		respB:  []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`),
	}

	h := NewVirtualMCPRouteHandler(c, vroutesTestNamespace, authsvc.NewInMemoryAssignmentStore(), ugSvc, dispatcher)
	return h, c, dispatcher, userStore
}

// vrouteCR builds a Ready VirtualMCPRoute CR with the given resolved
// entries and (optional) ACL ref names.
func vrouteCR(name string, aclRefs []string, entries []mcpv1alpha1.ResolvedEntry) *mcpv1alpha1.VirtualMCPRoute {
	acl := make([]corev1.LocalObjectReference, 0, len(aclRefs))
	for _, r := range aclRefs {
		acl = append(acl, corev1.LocalObjectReference{Name: r})
	}
	return &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vroutesTestNamespace},
		Spec: mcpv1alpha1.VirtualMCPRouteSpec{
			Sources: []mcpv1alpha1.VirtualMCPSource{{
				AdapterRef: &corev1.LocalObjectReference{Name: "src-adapter"},
			}},
			ACL: acl,
		},
		Status: mcpv1alpha1.VirtualMCPRouteStatus{
			Phase:           mcpv1alpha1.VirtualMCPRoutePhaseReady,
			ResolvedEntries: entries,
		},
	}
}

func vrouteRequest(routeName, userID, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vroutes/"+routeName+"/mcp", bytes.NewReader([]byte(body)))
	if userID != "" {
		req.Header.Set("X-User-ID", userID)
	}
	return req
}

// --- tools/list ------------------------------------------------------------------

func TestVRoute_ToolsList_ReturnsAggregatedCatalog(t *testing.T) {
	cr := vrouteCR("rt1", nil, []mcpv1alpha1.ResolvedEntry{
		{Name: "alpha", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter"},
		{Name: "beta", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter", OriginalName: "raw-beta"},
		{Name: "skip-resource", Kind: mcpv1alpha1.ResolvedEntryKindResource, SourceAdapter: "src-adapter"},
	})
	h, _, _, _ := newVRouteHandler(t, cr)

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice", `{"jsonrpc":"2.0","id":42,"method":"tools/list"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Result.Tools) != 2 {
		t.Fatalf("want 2 tools (alpha, beta) — got %d (%+v)", len(resp.Result.Tools), resp.Result.Tools)
	}
	got := map[string]bool{resp.Result.Tools[0].Name: true, resp.Result.Tools[1].Name: true}
	if !got["alpha"] || !got["beta"] {
		t.Errorf("want {alpha,beta}, got %+v", got)
	}
}

// --- tools/call dispatch --------------------------------------------------------

func TestVRoute_ToolsCall_RewritesAndDispatches(t *testing.T) {
	cr := vrouteCR("rt1", nil, []mcpv1alpha1.ResolvedEntry{
		{Name: "beta", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter", OriginalName: "raw-beta"},
	})
	h, _, disp, _ := newVRouteHandler(t, cr)

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"beta","arguments":{"k":"v"}}}`
	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	last := disp.lastCall()
	if last.AdapterID != "src-adapter" {
		t.Errorf("dispatched to %q, want src-adapter", last.AdapterID)
	}
	if last.UserID != "alice" {
		t.Errorf("userID = %q, want alice", last.UserID)
	}

	// The dispatched body should have params.name rewritten to the
	// origin's pre-rewrite name (raw-beta), with everything else preserved.
	var dispatched map[string]any
	if err := json.Unmarshal(last.Body, &dispatched); err != nil {
		t.Fatalf("decode dispatched body: %v", err)
	}
	params, ok := dispatched["params"].(map[string]any)
	if !ok {
		t.Fatalf("params missing or wrong shape: %+v", dispatched)
	}
	if params["name"] != "raw-beta" {
		t.Errorf("rewritten params.name = %v, want raw-beta", params["name"])
	}
	if args, ok := params["arguments"].(map[string]any); !ok || args["k"] != "v" {
		t.Errorf("arguments mangled: %+v", params["arguments"])
	}
}

func TestVRoute_ToolsCall_UnknownToolErrors(t *testing.T) {
	cr := vrouteCR("rt1", nil, []mcpv1alpha1.ResolvedEntry{
		{Name: "alpha", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter"},
	})
	h, _, _, _ := newVRouteHandler(t, cr)

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice",
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"ghost","arguments":{}}}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (JSON-RPC error wrapped in 200), got %d", rec.Code)
	}
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != jsonRPCMethodNotFound {
		t.Errorf("want JSON-RPC method-not-found, got %+v", resp)
	}
}

func TestVRoute_ToolsCall_MCPServerSourceErrors(t *testing.T) {
	cr := vrouteCR("rt1", nil, []mcpv1alpha1.ResolvedEntry{
		{Name: "beta", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceMCPServer: "srv1"}, // no SourceAdapter
	})
	h, _, _, _ := newVRouteHandler(t, cr)

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice",
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"beta","arguments":{}}}`))
	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != jsonRPCInternalError {
		t.Errorf("want JSON-RPC internal error for MCPServer-source dispatch, got %+v", resp)
	}
}

// --- ACL ------------------------------------------------------------------------

func TestVRoute_ACL_MatchedUserAllowed(t *testing.T) {
	cr := vrouteCR("rt1", []string{"team-acl"}, []mcpv1alpha1.ResolvedEntry{
		{Name: "alpha", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter"},
	})
	h, _, _, userStore := newVRouteHandler(t, cr)
	// Seed the assignment registry with team-acl matching alice via group.
	reg := h.assignmentRegistry.(*authsvc.InMemoryAssignmentStore)
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: vroutesTestNamespace + "/team-acl", Namespace: vroutesTestNamespace, Name: "team-acl",
		Users:       []string{"alice"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})
	_ = userStore.Create(context.Background(), models.User{ID: "alice"})

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestVRoute_ACL_UnmatchedUserForbidden(t *testing.T) {
	cr := vrouteCR("rt1", []string{"team-acl"}, []mcpv1alpha1.ResolvedEntry{
		{Name: "alpha", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter"},
	})
	h, _, _, userStore := newVRouteHandler(t, cr)
	reg := h.assignmentRegistry.(*authsvc.InMemoryAssignmentStore)
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: vroutesTestNamespace + "/team-acl", Namespace: vroutesTestNamespace, Name: "team-acl",
		Users:       []string{"alice"}, // bob is NOT in here
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})
	_ = userStore.Create(context.Background(), models.User{ID: "bob"})

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "bob", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestVRoute_ACL_EmptyFailOpen(t *testing.T) {
	cr := vrouteCR("rt1", nil, []mcpv1alpha1.ResolvedEntry{
		{Name: "alpha", Kind: mcpv1alpha1.ResolvedEntryKindTool, SourceAdapter: "src-adapter"},
	})
	h, _, _, _ := newVRouteHandler(t, cr)

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "anyone", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (empty ACL → fail-open), got %d", rec.Code)
	}
}

// --- misc -----------------------------------------------------------------------

func TestVRoute_RouteNotFound(t *testing.T) {
	h, _, _, _ := newVRouteHandler(t) // no CR

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("missing", "alice", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestVRoute_UnsupportedMethod(t *testing.T) {
	cr := vrouteCR("rt1", nil, nil)
	h, _, _, _ := newVRouteHandler(t, cr)

	rec := httptest.NewRecorder()
	h.HandleVirtualMCPProtocol(rec, vrouteRequest("rt1", "alice", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != jsonRPCMethodNotFound {
		t.Errorf("want JSON-RPC method-not-found, got %+v", resp)
	}
}

func TestVRoute_BadPath(t *testing.T) {
	h, _, _, _ := newVRouteHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vroutes/rt1", nil)
	h.HandleVirtualMCPProtocol(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}
