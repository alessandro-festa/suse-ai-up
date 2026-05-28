/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4d CR write-path unit tests. The handler talks to a fake
// controller-runtime client (no API server), so these exercise the
// projection / polling / TRENTO-expansion logic in isolation. Reconciler
// behavior is simulated by mutating Status on the fake client when the
// test wants the poll loop to observe Ready.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

const testNamespace = "test-ns"

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	return scheme
}

func newTestHandler(t *testing.T, objs ...client.Object) (*AdapterHandler, client.Client) {
	t.Helper()
	scheme := newTestScheme(t)
	// WithStatusSubresource is required for clients that call .Status().Update;
	// the handler uses .Update directly, but flipping Ready in tests via
	// .Status().Update needs the subresource declared.
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&mcpv1alpha1.Adapter{}).
		Build()
	h := &AdapterHandler{crClient: c, namespace: testNamespace}
	return h, c
}

// flipReady marks Ready=True on the named Adapter so a poll loop running
// concurrently observes the transition. Mirrors what AdapterReconciler
// would do after successful Deployment+Service materialization.
func flipReady(t *testing.T, c client.Client, name, endpointURL string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	var cr mcpv1alpha1.Adapter
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, &cr); err != nil {
		t.Fatalf("get adapter %s: %v", name, err)
	}
	cr.Status.EndpointURL = endpointURL
	cr.Status.Conditions = []metav1.Condition{{
		Type:               mcpv1alpha1.AdapterConditionReady,
		Status:             status,
		Reason:             reason,
		LastTransitionTime: metav1.Now(),
	}}
	if err := c.Status().Update(context.Background(), &cr); err != nil {
		t.Fatalf("flip Ready on %s: %v", name, err)
	}
}

// TestCreateAdapter_CRPath_HappyPath exercises the full handler:
// POST → CR create → reconciler flips Ready → poll returns ready → 201.
func TestCreateAdapter_CRPath_HappyPath(t *testing.T) {
	h, c := newTestHandler(t)

	body, _ := json.Marshal(CreateAdapterRequest{
		MCPServerID: "some-server",
		Name:        "smoke-adapter",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "alice")
	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Tight loop: flip Ready as soon as the CR exists. Avoids
		// brittle sleeps while still proving the poll loop observes
		// the transition.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Adapter
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "smoke-adapter"}, &cr); err == nil {
				flipReady(t, c, "smoke-adapter", "http://proxy/smoke-adapter", metav1.ConditionTrue, "Ready")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateAdapter(rec, req)
	wg.Wait()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp CreateAdapterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if resp.Status != "ready" {
		t.Errorf("status = %q, want %q", resp.Status, "ready")
	}
	if resp.ID != "smoke-adapter" {
		t.Errorf("id = %q, want smoke-adapter", resp.ID)
	}

	// Verify the CR carries the createdBy annotation so the read
	// projection can recover owner identity.
	var cr mcpv1alpha1.Adapter
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "smoke-adapter"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if got := cr.Annotations[adapterAnnotationCreatedBy]; got != "alice" {
		t.Errorf("createdBy annotation = %q, want alice", got)
	}
}

// TestCreateAdapter_CRPath_PollTimeout: no condition flip → handler
// returns 201 with status="provisioning" so the UI can poll GET.
func TestCreateAdapter_CRPath_PollTimeout(t *testing.T) {
	// Tighten the poll budget for the test so it doesn't take 5s.
	origTimeout, origInterval := adapterPollTimeout, adapterPollInterval
	t.Cleanup(func() {
		// adapterPollTimeout/Interval are package-level consts; the
		// test redefines them by shadowing through package-level
		// variables instead. Restoring is a noop here, kept for
		// readability if these ever become vars.
		_ = origTimeout
		_ = origInterval
	})

	h, _ := newTestHandler(t)
	// Cancel the request context shortly after Create returns so the
	// poll loop bails out fast (it returns "provisioning" on ctx.Done).
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	body, _ := json.Marshal(CreateAdapterRequest{
		MCPServerID: "some-server",
		Name:        "slow-adapter",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()

	h.CreateAdapter(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp CreateAdapterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "provisioning" {
		t.Errorf("status = %q, want provisioning (poll timed out)", resp.Status)
	}
}

// TestCreateAdapter_CRPath_TerminalFailure: reconciler sets Ready=False
// with a terminal reason → handler returns 201 with status="error".
// (201 because the CR was created; the body status reflects reconcile
// failure so the UI surfaces the error without separate plumbing.)
func TestCreateAdapter_CRPath_TerminalFailure(t *testing.T) {
	h, c := newTestHandler(t)

	body, _ := json.Marshal(CreateAdapterRequest{
		MCPServerID: "bad-server",
		Name:        "bad-adapter",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Adapter
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "bad-adapter"}, &cr); err == nil {
				flipReady(t, c, "bad-adapter", "", metav1.ConditionFalse, "MissingSidecarConfig")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateAdapter(rec, req)

	var resp CreateAdapterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("status = %q, want error", resp.Status)
	}
}

// TestCreateAdapter_CRPath_TrentoExpansion: TRENTO_CONFIG → bearer Secret
// gets created paired to the Adapter, TRENTO_URL replaces TRENTO_CONFIG
// in Variables, CR.Spec.Authentication.BearerToken.SecretRef points at
// the new Secret.
func TestCreateAdapter_CRPath_TrentoExpansion(t *testing.T) {
	h, c := newTestHandler(t)

	// TRENTO_CONFIG is the comma-delimited "TRENTO_URL={url},TOKEN={pat}"
	// shape ParseTrentoConfig accepts.
	trentoCfg := "TRENTO_URL=https://trento.example.com,TOKEN=abc-token-123"
	body, _ := json.Marshal(CreateAdapterRequest{
		MCPServerID:          "suse-trento",
		Name:                 "trento-adapter",
		EnvironmentVariables: map[string]string{"TRENTO_CONFIG": trentoCfg},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var cr mcpv1alpha1.Adapter
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "trento-adapter"}, &cr); err == nil {
				flipReady(t, c, "trento-adapter", "http://proxy/trento-adapter", metav1.ConditionTrue, "Ready")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	h.CreateAdapter(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// CR shape checks.
	var cr mcpv1alpha1.Adapter
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "trento-adapter"}, &cr); err != nil {
		t.Fatalf("get adapter CR: %v", err)
	}
	if v, ok := cr.Spec.Variables["TRENTO_URL"]; !ok || v != "https://trento.example.com" {
		t.Errorf("TRENTO_URL = %q (present=%v), want https://trento.example.com", v, ok)
	}
	if _, ok := cr.Spec.Variables["TRENTO_CONFIG"]; ok {
		t.Errorf("TRENTO_CONFIG should be stripped after expansion")
	}
	if cr.Spec.Authentication == nil || cr.Spec.Authentication.BearerToken == nil || cr.Spec.Authentication.BearerToken.SecretRef == nil {
		t.Fatalf("expected bearer SecretRef on CR; got %+v", cr.Spec.Authentication)
	}
	wantSecretName := "adapter-trento-adapter-bearer"
	if got := cr.Spec.Authentication.BearerToken.SecretRef.Name; got != wantSecretName {
		t.Errorf("SecretRef.Name = %q, want %q", got, wantSecretName)
	}

	// Paired Secret must exist with the token populated.
	var secret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: wantSecretName}, &secret); err != nil {
		t.Fatalf("get bearer secret: %v", err)
	}
	if got := string(secret.Data["token"]); got != "abc-token-123" {
		// fake.Client materializes StringData into Data on Create.
		if got2 := secret.StringData["token"]; got2 != "abc-token-123" {
			t.Errorf("secret token = %q / stringData=%q, want abc-token-123", got, got2)
		}
	}
	// OwnerReference must cascade-delete with the Adapter.
	foundOwner := false
	for _, owner := range secret.OwnerReferences {
		if owner.Kind == "Adapter" && owner.Name == "trento-adapter" {
			foundOwner = true
			break
		}
	}
	if !foundOwner {
		t.Errorf("bearer secret missing Adapter OwnerReference; got %+v", secret.OwnerReferences)
	}
}

// TestCreateAdapter_CRPath_AlreadyExists: re-POST same name → 409.
func TestCreateAdapter_CRPath_AlreadyExists(t *testing.T) {
	existing := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "dup", Namespace: testNamespace},
	}
	h, _ := newTestHandler(t, existing)

	body, _ := json.Marshal(CreateAdapterRequest{MCPServerID: "x", Name: "dup"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreateAdapter(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDeleteAdapter_CRPath: CR is removed; 404 on missing.
func TestDeleteAdapter_CRPath(t *testing.T) {
	existing := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "todelete", Namespace: testNamespace},
	}
	h, c := newTestHandler(t, existing)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/adapters/todelete", nil)
	rec := httptest.NewRecorder()
	h.DeleteAdapter(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.Adapter
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "todelete"}, &cr)
	if err == nil || !apierrors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got err=%v", err)
	}

	// Re-delete → 404.
	rec2 := httptest.NewRecorder()
	h.DeleteAdapter(rec2, httptest.NewRequest(http.MethodDelete, "/api/v1/adapters/todelete", nil))
	if rec2.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", rec2.Code)
	}
}

// TestSyncAdapterCapabilities_CRPath: bumps the sync annotation; missing
// CR yields 404.
func TestSyncAdapterCapabilities_CRPath(t *testing.T) {
	existing := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "syncme", Namespace: testNamespace},
	}
	h, c := newTestHandler(t, existing)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters/syncme/sync", nil)
	rec := httptest.NewRecorder()
	h.SyncAdapterCapabilities(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var cr mcpv1alpha1.Adapter
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: "syncme"}, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	if _, ok := cr.Annotations[adapterAnnotationSyncRequested]; !ok {
		t.Errorf("sync annotation not stamped; annotations=%+v", cr.Annotations)
	}
}

// TestCheckAdapterHealth_CRPath: returns the Ready condition projection.
func TestCheckAdapterHealth_CRPath(t *testing.T) {
	existing := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "healthme", Namespace: testNamespace},
	}
	h, c := newTestHandler(t, existing)
	flipReady(t, c, "healthme", "http://proxy/healthme", metav1.ConditionTrue, "Ready")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters/healthme/health", nil)
	rec := httptest.NewRecorder()
	h.CheckAdapterHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.EqualFold(body["status"], string(models.AdapterLifecycleStatusReady)) {
		t.Errorf("status = %q, want %q", body["status"], models.AdapterLifecycleStatusReady)
	}
}

// TestTranslateAdapterAuth_Bearer: inline token → paired Secret +
// BearerToken.SecretRef.
func TestTranslateAdapterAuth_Bearer(t *testing.T) {
	auth, secret, err := translateAdapterAuth(&models.AdapterAuthConfig{
		Type: "bearer",
		BearerToken: &models.BearerTokenConfig{
			Token: "tok",
		},
	}, "a", testNamespace)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if secret == nil || secret.StringData["token"] != "tok" {
		t.Fatalf("expected secret with token; got %+v", secret)
	}
	if auth.BearerToken == nil || auth.BearerToken.SecretRef == nil {
		t.Fatalf("expected SecretRef; got %+v", auth.BearerToken)
	}
	if auth.BearerToken.SecretRef.Name != "adapter-a-bearer" {
		t.Errorf("secretRef name = %q", auth.BearerToken.SecretRef.Name)
	}
}

// TestTranslateAdapterAuth_BearerDynamic: dynamic=true → no Secret, just
// the Dynamic flag carried.
func TestTranslateAdapterAuth_BearerDynamic(t *testing.T) {
	auth, secret, err := translateAdapterAuth(&models.AdapterAuthConfig{
		Type:        "bearer",
		BearerToken: &models.BearerTokenConfig{Dynamic: true},
	}, "a", testNamespace)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if secret != nil {
		t.Errorf("dynamic bearer should not create secret; got %+v", secret)
	}
	if !auth.BearerToken.Dynamic {
		t.Errorf("Dynamic flag lost in translation")
	}
}

// TestTranslateAdapterAuth_NoneRequiredFalse: none → Required=false.
func TestTranslateAdapterAuth_NoneRequiredFalse(t *testing.T) {
	auth, _, err := translateAdapterAuth(&models.AdapterAuthConfig{Type: "none"}, "a", testNamespace)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if auth.Required {
		t.Errorf("type=none must produce Required=false")
	}
}

// TestIsTerminalAdapterReason guards the reason strings the handler
// trusts as terminal — adding new ones requires adding tests so we
// don't accidentally treat transient reasons as final.
func TestIsTerminalAdapterReason(t *testing.T) {
	cases := map[string]bool{
		"MissingSidecarConfig":   true,
		"UnsupportedCommandType": true,
		"InvalidSpec":            true,
		"Reconciling":            false,
		"":                       false,
	}
	for reason, want := range cases {
		if got := isTerminalAdapterReason(reason); got != want {
			t.Errorf("isTerminalAdapterReason(%q) = %v, want %v", reason, got, want)
		}
	}
}
