/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4e CR write-path unit tests for PluginHandler. The handler talks
// to a fake controller-runtime client (no API server), so these test
// the projection / polling / fall-through-to-legacy logic in isolation.
// Reconciler behavior is simulated by mutating Status on the fake
// client when the test wants the poll loop to observe Registered.
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
	"github.com/SUSE/suse-ai-up/pkg/plugins"
)

const pluginTestNamespace = "test-ns"

func init() {
	// Silence gin in tests.
	gin.SetMode(gin.TestMode)
}

func newPluginTestHandler(t *testing.T, objs ...client.Object) (*PluginHandler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.Plugin{}).
		Build()
	h := &PluginHandler{
		crClient:  c,
		namespace: pluginTestNamespace,
		// serviceManager intentionally nil — CR path must not touch it.
	}
	return h, c
}

// flipPluginRegistered marks Registered=True on the named Plugin so a
// poll loop running concurrently observes the transition. Mirrors the
// PluginReconciler's first-reconcile behavior.
func flipPluginRegistered(t *testing.T, c client.Client, name string) {
	t.Helper()
	var cr mcpv1alpha1.Plugin
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: pluginTestNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get plugin %s: %v", name, err)
	}
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.PluginConditionRegistered,
		Status:             metav1.ConditionTrue,
		Reason:             "Projected",
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Registered on %s: %v", name, err)
	}
}

// newGinContext wraps a recorder + request into the gin.Context shape
// the handler expects (Param lookups, JSON binding, etc.).
func newGinContext(method, path string, body []byte, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
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

// TestRegisterService_CRPath_HappyPath: POST → CR create → reconciler
// flips Registered → poll returns "registered" → 201.
func TestRegisterService_CRPath_HappyPath(t *testing.T) {
	h, c := newPluginTestHandler(t)

	body, _ := json.Marshal(RegisterServiceRequest{
		ServiceID:   "smoke-plugin",
		ServiceType: "smartagents",
		ServiceURL:  "http://example.com",
		Version:     "v1.0",
	})
	ctx, rec := newGinContext(http.MethodPost, "/api/v1/plugins/register", body, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Plugin
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: pluginTestNamespace, Name: "smoke-plugin"}, &cr); err == nil {
				flipPluginRegistered(t, c, "smoke-plugin")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.RegisterService(ctx)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp RegisterServiceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "registered" {
		t.Errorf("status = %q, want registered", resp.Status)
	}
	if resp.ServiceID != "smoke-plugin" {
		t.Errorf("service_id = %q, want smoke-plugin", resp.ServiceID)
	}

	// CR was created with the right Spec.
	var cr mcpv1alpha1.Plugin
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: pluginTestNamespace, Name: "smoke-plugin"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if cr.Spec.ServiceURL != "http://example.com" {
		t.Errorf("ServiceURL = %q", cr.Spec.ServiceURL)
	}
	if string(cr.Spec.ServiceType) != "smartagents" {
		t.Errorf("ServiceType = %q", cr.Spec.ServiceType)
	}
}

// TestRegisterService_CRPath_PollTimeout: no Registered flip → 201
// with status="provisioning" so the UI knows to poll.
func TestRegisterService_CRPath_PollTimeout(t *testing.T) {
	h, _ := newPluginTestHandler(t)
	// Cancel the request context fast so pollPluginRegistered exits
	// via ctx.Done rather than waiting the full 5s budget.
	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	body, _ := json.Marshal(RegisterServiceRequest{
		ServiceID:   "slow-plugin",
		ServiceType: "smartagents",
		ServiceURL:  "http://example.com",
	})
	ctx, rec := newGinContext(http.MethodPost, "/api/v1/plugins/register", body, nil)
	ctx.Request = ctx.Request.WithContext(cctx)

	h.RegisterService(ctx)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp RegisterServiceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "provisioning" {
		t.Errorf("status = %q, want provisioning", resp.Status)
	}
}

// TestRegisterService_CRPath_AlreadyExists: re-POST same id → 409,
// preserving today's HTTP semantic.
func TestRegisterService_CRPath_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: pluginTestNamespace},
		Spec:       mcpv1alpha1.PluginSpec{ServiceURL: "http://x"},
	}
	h, _ := newPluginTestHandler(t, existing)

	body, _ := json.Marshal(RegisterServiceRequest{
		ServiceID:   "dup",
		ServiceType: "smartagents",
		ServiceURL:  "http://example.com",
	})
	ctx, rec := newGinContext(http.MethodPost, "/api/v1/plugins/register", body, nil)

	h.RegisterService(ctx)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestUnregisterService_CRPath: deletes the CR; 404 on missing.
func TestUnregisterService_CRPath(t *testing.T) {
	existing := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: "byebye", Namespace: pluginTestNamespace},
		Spec:       mcpv1alpha1.PluginSpec{ServiceURL: "http://x"},
	}
	h, c := newPluginTestHandler(t, existing)

	ctx, _ := newGinContext(http.MethodDelete, "/api/v1/plugins/register/byebye", nil, gin.Params{{Key: "serviceId", Value: "byebye"}})
	h.UnregisterService(ctx)

	if got := ctx.Writer.Status(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", got)
	}
	var cr mcpv1alpha1.Plugin
	err := c.Get(context.Background(), client.ObjectKey{Namespace: pluginTestNamespace, Name: "byebye"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got err=%v", err)
	}

	// Re-delete → 404.
	ctx2, _ := newGinContext(http.MethodDelete, "/api/v1/plugins/register/byebye", nil, gin.Params{{Key: "serviceId", Value: "byebye"}})
	h.UnregisterService(ctx2)
	if got := ctx2.Writer.Status(); got != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", got)
	}
}

// TestTranslatePluginCapabilities preserves Path/Methods/Description
// 1:1 and returns nil for empty input (matches the CR convention).
func TestTranslatePluginCapabilities(t *testing.T) {
	if got := translatePluginCapabilities(nil); got != nil {
		t.Errorf("nil input should return nil, got %+v", got)
	}
	if got := translatePluginCapabilities([]plugins.ServiceCapability{}); got != nil {
		t.Errorf("empty input should return nil, got %+v", got)
	}
	in := []plugins.ServiceCapability{
		{Path: "/a", Methods: []string{"GET", "POST"}, Description: "alpha"},
		{Path: "/b/*", Methods: nil, Description: ""},
	}
	out := translatePluginCapabilities(in)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Path != "/a" || len(out[0].Methods) != 2 || out[0].Description != "alpha" {
		t.Errorf("out[0] = %+v", out[0])
	}
	if out[1].Path != "/b/*" || len(out[1].Methods) != 0 {
		t.Errorf("out[1] = %+v", out[1])
	}
}

// TestRegisterServiceResponse_HasStatusField guards the additive DTO
// change — accidentally removing the field would silently break the
// UI's poll-on-provisioning flow.
func TestRegisterServiceResponse_HasStatusField(t *testing.T) {
	resp := RegisterServiceResponse{ServiceID: "x", Message: "ok", Status: "registered"}
	b, _ := json.Marshal(resp)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["status"]; !ok {
		t.Errorf("RegisterServiceResponse JSON missing \"status\" key: %s", string(b))
	}
}
