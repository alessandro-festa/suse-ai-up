/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5c AgentHandler tests. The handler is exercised against:
//   - a fake controller-runtime client seeded with Agent CRs (Spec.ACL)
//   - an InMemoryAgentStore seeded with RegisteredAgents
//   - a swappable stub protocol the test asserts on
//   - a stub MCPDispatcher (reused pattern from vroutes_mcp_test.go)
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/SUSE/suse-ai-up/pkg/services/agents"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

const agentsTestNamespace = "test-ns"

// recorderProtocol is a swappable AgentProtocol stub that records the
// InvocationContext it receives and writes a canned response. Lets the
// tests assert on the agent + dispatcher passed to the protocol without
// pulling in the smartagents stub.
type recorderProtocol struct {
	name string
	mu   sync.Mutex
	last *agents.InvocationContext
	body string
	code int
	// If acceptToolName is non-empty, the protocol attempts to dispatch
	// to it via ic.Dispatcher (mimics a real protocol enforcing tool ACL
	// before invoking the dispatcher).
	dispatchTo string
}

func (p *recorderProtocol) Name() string                     { return p.name }
func (p *recorderProtocol) Capabilities() []agents.Capability { return nil }
func (p *recorderProtocol) EnforceACL(context.Context, string, string) error {
	return nil
}
func (p *recorderProtocol) HandleRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, ic agents.InvocationContext) {
	p.mu.Lock()
	p.last = &ic
	p.mu.Unlock()

	// Resource-level tool ACL: only dispatch to an adapter in
	// ic.Agent.Tools. Reject otherwise. Real protocols do this when
	// translating a protocol-specific call into an MCP invocation.
	if p.dispatchTo != "" {
		allowed := false
		for _, t := range ic.Agent.Tools {
			if t.AdapterName == p.dispatchTo {
				allowed = true
				break
			}
		}
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"tool not in agent.Spec.Tools"}`))
			return
		}
		// Allowed — try the dispatcher (will hit the stub).
		_, _, _, _ = ic.Dispatcher.ProxyMCPToAdapter(ctx, p.dispatchTo, ic.UserID, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`), r.Header)
	}

	w.Header().Set("Content-Type", "application/json")
	if p.code == 0 {
		p.code = http.StatusOK
	}
	w.WriteHeader(p.code)
	_, _ = w.Write([]byte(p.body))
}

func (p *recorderProtocol) lastCall() *agents.InvocationContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

func newAgentTestHandler(t *testing.T, protocolName string, protocol agents.AgentProtocol, registered *agents.RegisteredAgent, aclRefs []string, withCR bool) (*AgentHandler, *stubDispatcher) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}

	var objs []client.Object
	if withCR && registered != nil {
		acl := make([]corev1.LocalObjectReference, 0, len(aclRefs))
		for _, n := range aclRefs {
			acl = append(acl, corev1.LocalObjectReference{Name: n})
		}
		cr := &mcpv1alpha1.Agent{
			ObjectMeta: metav1.ObjectMeta{Name: registered.Name, Namespace: agentsTestNamespace},
			Spec:       mcpv1alpha1.AgentSpec{Protocol: registered.Protocol, ACL: acl},
		}
		objs = append(objs, cr)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.Agent{}).
		Build()

	store := agents.NewInMemoryAgentStore()
	if registered != nil {
		_ = store.UpsertAgent(registered)
	}

	registry := agents.NewRegistry()
	if protocol != nil {
		registry.Register(protocolName, protocol)
	}

	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	ugSvc := services.NewUserGroupService(userStore, groupStore)

	disp := &stubDispatcher{
		respSC: http.StatusOK,
		respCT: "application/json",
		respB:  []byte(`{"result":"ok"}`),
	}

	h := NewAgentHandler(c, agentsTestNamespace, store, registry, authsvc.NewInMemoryAssignmentStore(), ugSvc, disp)
	return h, disp
}

func agentRequest(agentName, protocolPath, userID string) *http.Request {
	url := "/api/v1/agents/" + agentName
	if protocolPath != "" {
		if !strings.HasPrefix(protocolPath, "/") {
			protocolPath = "/" + protocolPath
		}
		url += protocolPath
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"hello":"world"}`)))
	if userID != "" {
		req.Header.Set("X-User-ID", userID)
	}
	return req
}

func regAgent(name, protocol string, tools ...agents.ToolRef) *agents.RegisteredAgent {
	return &agents.RegisteredAgent{
		ID:        agentsTestNamespace + "/" + name,
		Namespace: agentsTestNamespace,
		Name:      name,
		Protocol:  protocol,
		Tools:     tools,
	}
}

// --- happy path -----------------------------------------------------------------

func TestAgent_HappyPath_DispatchesToProtocol(t *testing.T) {
	proto := &recorderProtocol{name: "rec", body: `{"ok":true}`, code: http.StatusOK}
	h, _ := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec", agents.ToolRef{AdapterName: "src"}),
		nil, true)

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/anything/here", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	got := proto.lastCall()
	if got == nil {
		t.Fatal("protocol never invoked")
	}
	if got.UserID != "alice" {
		t.Errorf("UserID = %q, want alice", got.UserID)
	}
	if got.Agent == nil || got.Agent.Name != "ag1" {
		t.Errorf("Agent in InvocationContext: %+v", got.Agent)
	}
	if got.Dispatcher == nil {
		t.Error("Dispatcher should be wired")
	}
}

// --- agent not found in store --------------------------------------------------

func TestAgent_NotFoundInStore_404(t *testing.T) {
	h, _ := newAgentTestHandler(t, "rec", &recorderProtocol{name: "rec"}, nil, nil, false)

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("missing", "/anything", "alice"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

// --- protocol not registered ---------------------------------------------------

func TestAgent_ProtocolNotRegistered_501(t *testing.T) {
	// Registered agent declares "a2a" but no implementation is in the registry.
	h, _ := newAgentTestHandler(t, "rec", &recorderProtocol{name: "rec"},
		regAgent("ag1", "a2a"), nil, true)

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "alice"))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("want 501, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Agent protocol not registered") {
		t.Errorf("body = %q, want protocol-not-registered message", rec.Body.String())
	}
}

// --- ACL ------------------------------------------------------------------------

func TestAgent_ACL_MatchedUserAllowed(t *testing.T) {
	proto := &recorderProtocol{name: "rec", body: `{"ok":true}`, code: http.StatusOK}
	h, _ := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec"), []string{"team-acl"}, true)

	reg := h.assignmentRegistry.(*authsvc.InMemoryAssignmentStore)
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: agentsTestNamespace + "/team-acl", Namespace: agentsTestNamespace, Name: "team-acl",
		Users:       []string{"alice"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgent_ACL_UnmatchedUserForbidden(t *testing.T) {
	proto := &recorderProtocol{name: "rec", body: `{"ok":true}`, code: http.StatusOK}
	h, _ := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec"), []string{"team-acl"}, true)

	reg := h.assignmentRegistry.(*authsvc.InMemoryAssignmentStore)
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: agentsTestNamespace + "/team-acl", Namespace: agentsTestNamespace, Name: "team-acl",
		Users:       []string{"alice"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})
	// Seed bob so GetUser returns a User with no groups (not 'alice').
	userStore := clients.NewInMemoryUserStore()
	_ = userStore.Create(context.Background(), models.User{ID: "bob"})

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "bob"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
	if proto.lastCall() != nil {
		t.Error("protocol should NOT have been invoked when ACL fails")
	}
}

func TestAgent_ACL_EmptyFailOpen(t *testing.T) {
	proto := &recorderProtocol{name: "rec", body: `{"ok":true}`, code: http.StatusOK}
	h, _ := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec"), nil, true) // no ACL refs

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "anyone"))
	if rec.Code != http.StatusOK {
		t.Errorf("want 200 (empty ACL → fail-open), got %d", rec.Code)
	}
}

// --- resource-level tool ACL via protocol contract -----------------------------

func TestAgent_ToolACL_ProtocolAllowsListedAdapter(t *testing.T) {
	// Agent.Spec.Tools lists "src". The recorderProtocol dispatches
	// to "src" → allowed; dispatcher.calls increments by 1.
	proto := &recorderProtocol{name: "rec", body: `{"ok":true}`, code: http.StatusOK, dispatchTo: "src"}
	h, disp := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec", agents.ToolRef{AdapterName: "src"}),
		nil, true)

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(disp.calls) != 1 {
		t.Errorf("expected 1 dispatcher call for the allowed adapter, got %d", len(disp.calls))
	}
}

func TestAgent_ToolACL_ProtocolRejectsUnlistedAdapter(t *testing.T) {
	// Agent.Spec.Tools lists "allowed" but the protocol tries to dispatch
	// to "forbidden" — the protocol stub returns 403 without invoking the
	// dispatcher, mimicking what real protocols must do.
	proto := &recorderProtocol{name: "rec", dispatchTo: "forbidden"}
	h, disp := newAgentTestHandler(t, "rec", proto,
		regAgent("ag1", "rec", agents.ToolRef{AdapterName: "allowed"}),
		nil, true)

	rec := httptest.NewRecorder()
	h.HandleAgentProtocol(rec, agentRequest("ag1", "/x", "alice"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 (protocol enforced tool ACL), got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(disp.calls) != 0 {
		t.Errorf("dispatcher should not have been called when tool ACL rejects, got %d calls", len(disp.calls))
	}
}

// --- misc -----------------------------------------------------------------------

func TestAgent_BadPath_NoAgentName(t *testing.T) {
	h, _ := newAgentTestHandler(t, "rec", &recorderProtocol{name: "rec"}, nil, nil, false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/", nil)
	h.HandleAgentProtocol(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}
