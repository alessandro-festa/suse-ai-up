/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Agent CRUD handler unit tests. The handler talks to a fake
// controller-runtime client (no API server); these exercise the
// projection / polling / validation logic in isolation. Reconciler
// behavior is simulated by mutating Status on the fake client when the
// test wants the poll loop to observe Ready.
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

// newAgentCRUDTestHandler builds an AgentHandler wired against a fake CR
// client + in-memory UserGroupService. dev-admin short-circuits
// CanManageGroups so most tests can reach past the permission gate by
// setting X-User-ID: dev-admin.
func newAgentCRUDTestHandler(t *testing.T, objs ...client.Object) (*AgentHandler, client.Client) {
	t.Helper()
	scheme := newTestScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.Agent{}).
		Build()

	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)

	h := &AgentHandler{
		crClient:         c,
		namespace:        testNamespace,
		userGroupService: svc,
	}
	return h, c
}

// flipAgentReady mirrors flipReady (adapters): mark Ready on the named
// Agent so a concurrent poll observes the transition.
func flipAgentReady(t *testing.T, c client.Client, name, endpointURL string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	var cr mcpv1alpha1.Agent
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get agent %s: %v", name, err)
	}
	cr.Status.EndpointURL = endpointURL
	cr.Status.Phase = mcpv1alpha1.AgentPhaseReady
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.AgentConditionReady,
		Status:             status,
		Reason:             reason,
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on %s: %v", name, err)
	}
}

func TestCreateAgent_HappyPath(t *testing.T) {
	h, c := newAgentCRUDTestHandler(t)

	body, _ := json.Marshal(CreateAgentRequest{
		Name:        "weather-bot",
		Protocol:    "a2a",
		Description: "weather agent",
		Tools: []AgentToolDTO{
			{AdapterName: "weather-adapter"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Agent
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "weather-bot"}, &cr); err == nil {
				flipAgentReady(t, c, "weather-bot", "http://proxy/api/v1/agents/weather-bot", metav1.ConditionTrue, "Ready")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateAgent(rec, req)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp AgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.Status != agentStatusReady {
		t.Errorf("status = %q, want %q", resp.Status, agentStatusReady)
	}
	if resp.Name != "weather-bot" {
		t.Errorf("name = %q, want weather-bot", resp.Name)
	}
	if resp.Protocol != "a2a" {
		t.Errorf("protocol = %q, want a2a", resp.Protocol)
	}
	if len(resp.Tools) != 1 || resp.Tools[0].AdapterName != "weather-adapter" {
		t.Errorf("tools = %+v, want [{AdapterName: weather-adapter}]", resp.Tools)
	}

	var cr mcpv1alpha1.Agent
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "weather-bot"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if got := cr.Annotations[agentAnnotationCreatedBy]; got != "dev-admin" {
		t.Errorf("createdBy annotation = %q, want dev-admin", got)
	}
}

func TestCreateAgent_PollTimeout(t *testing.T) {
	h, _ := newAgentCRUDTestHandler(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	body, _ := json.Marshal(CreateAgentRequest{Name: "slow-agent", Protocol: "a2a"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()

	h.CreateAgent(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp AgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != agentStatusProvisioning {
		t.Errorf("status = %q, want provisioning", resp.Status)
	}
}

func TestCreateAgent_TerminalFailure(t *testing.T) {
	h, c := newAgentCRUDTestHandler(t)

	body, _ := json.Marshal(CreateAgentRequest{Name: "bad-agent", Protocol: "unregistered-protocol"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Agent
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "bad-agent"}, &cr); err == nil {
				flipAgentReady(t, c, "bad-agent", "", metav1.ConditionFalse, "ProtocolUnknown")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateAgent(rec, req)
	var resp AgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != agentStatusError {
		t.Errorf("status = %q, want error", resp.Status)
	}
}

func TestCreateAgent_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		req  CreateAgentRequest
		want string
	}{
		{"missing name", CreateAgentRequest{Protocol: "a2a"}, "name is required"},
		{"missing protocol", CreateAgentRequest{Name: "a"}, "protocol is required"},
		{"tool with both refs", CreateAgentRequest{
			Name:     "a",
			Protocol: "a2a",
			Tools:    []AgentToolDTO{{AdapterName: "x", VirtualMCPRouteName: "y"}},
		}, "exactly one of"},
		{"tool with neither ref", CreateAgentRequest{
			Name:     "a",
			Protocol: "a2a",
			Tools:    []AgentToolDTO{{}},
		}, "exactly one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newAgentCRUDTestHandler(t)
			body, _ := json.Marshal(tc.req)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
			req.Header.Set("X-User-ID", "dev-admin")
			rec := httptest.NewRecorder()
			h.CreateAgent(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
				t.Errorf("body=%s does not contain %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestCreateAgent_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: testNamespace},
		Spec:       mcpv1alpha1.AgentSpec{Protocol: "a2a"},
	}
	h, _ := newAgentCRUDTestHandler(t, existing)

	body, _ := json.Marshal(CreateAgentRequest{Name: "dup", Protocol: "a2a"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateAgent(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestCreateAgent_Forbidden — non-admin user without group:manage
// permission → 403. Empty userStore means no permissions resolved, so
// CanManageGroups returns (false, nil) for any user but dev-admin.
func TestCreateAgent_Forbidden(t *testing.T) {
	h, _ := newAgentCRUDTestHandler(t)

	body, _ := json.Marshal(CreateAgentRequest{Name: "a", Protocol: "a2a"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "alice")
	rec := httptest.NewRecorder()
	h.CreateAgent(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestListAgents_Sorted(t *testing.T) {
	objs := []client.Object{
		&mcpv1alpha1.Agent{
			ObjectMeta: metav1.ObjectMeta{Name: "zulu", Namespace: testNamespace},
			Spec:       mcpv1alpha1.AgentSpec{Protocol: "a2a"},
		},
		&mcpv1alpha1.Agent{
			ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: testNamespace},
			Spec:       mcpv1alpha1.AgentSpec{Protocol: "a2a"},
		},
	}
	h, _ := newAgentCRUDTestHandler(t, objs...)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	h.ListAgents(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []AgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 || out[0].Name != "alpha" || out[1].Name != "zulu" {
		t.Errorf("got names = %v, want [alpha zulu]", []string{out[0].Name, out[1].Name})
	}
}

func TestGetAgent_NotFound(t *testing.T) {
	h, _ := newAgentCRUDTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/missing", nil)
	rec := httptest.NewRecorder()
	h.GetAgent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAgent_ProtocolImmutable — even if a client sends a different
// protocol in the body, the CR keeps the original. The DTO doesn't carry
// Protocol at all, so this is enforced by construction.
func TestUpdateAgent_ToolsAndACL(t *testing.T) {
	existing := &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-x", Namespace: testNamespace},
		Spec: mcpv1alpha1.AgentSpec{
			Protocol: "a2a",
			Tools:    []mcpv1alpha1.AgentToolRef{{AdapterRef: &corev1.LocalObjectReference{Name: "old-adapter"}}},
		},
	}
	h, c := newAgentCRUDTestHandler(t, existing)

	body, _ := json.Marshal(UpdateAgentRequest{
		Description: "updated",
		Tools:       []AgentToolDTO{{AdapterName: "new-adapter"}},
		ACL:         []string{"my-assignment"},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/agents/agent-x", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateAgent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var cr mcpv1alpha1.Agent
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "agent-x"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Spec.Protocol != "a2a" {
		t.Errorf("Protocol mutated to %q, want a2a (immutable)", cr.Spec.Protocol)
	}
	if cr.Spec.Description != "updated" {
		t.Errorf("Description = %q, want updated", cr.Spec.Description)
	}
	if len(cr.Spec.Tools) != 1 || cr.Spec.Tools[0].AdapterRef == nil || cr.Spec.Tools[0].AdapterRef.Name != "new-adapter" {
		t.Errorf("Tools = %+v, want [{AdapterRef: new-adapter}]", cr.Spec.Tools)
	}
	if len(cr.Spec.ACL) != 1 || cr.Spec.ACL[0].Name != "my-assignment" {
		t.Errorf("ACL = %+v, want [{my-assignment}]", cr.Spec.ACL)
	}
}

func TestDeleteAgent(t *testing.T) {
	existing := &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: "todelete", Namespace: testNamespace},
		Spec:       mcpv1alpha1.AgentSpec{Protocol: "a2a"},
	}
	h, c := newAgentCRUDTestHandler(t, existing)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/todelete", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteAgent(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.Agent
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "todelete"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got err=%v", err)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/todelete", nil)
	req2.Header.Set("X-User-ID", "dev-admin")
	h.DeleteAgent(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", rec2.Code)
	}
}

func TestAgentNameFromPath(t *testing.T) {
	cases := map[string]string{
		"/api/v1/agents/foo":             "foo",
		"/api/v1/agents/foo/bar":         "foo",
		"/api/v1/agents/foo/bar/baz":     "foo",
		"/api/v1/agents/":                "",
		"/api/v1/adapters/foo":           "",
		"/other/path":                    "",
	}
	for in, want := range cases {
		if got := agentNameFromPath(in); got != want {
			t.Errorf("agentNameFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTerminalAgentReason(t *testing.T) {
	cases := map[string]bool{
		"ProtocolUnknown": true,
		"ToolMissing":     true,
		"InvalidSpec":     true,
		"Reconciling":     false,
		"":                false,
	}
	for reason, want := range cases {
		if got := isTerminalAgentReason(reason); got != want {
			t.Errorf("isTerminalAgentReason(%q) = %v, want %v", reason, got, want)
		}
	}
}

