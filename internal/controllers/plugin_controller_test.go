/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
)

func TestEffectiveHealthCheck_NilUsesDefaults(t *testing.T) {
	path, interval, timeout := effectiveHealthCheck(nil)
	if path != defaultPluginHealthPath {
		t.Errorf("path = %q, want %q", path, defaultPluginHealthPath)
	}
	if interval != defaultPluginIntervalSec {
		t.Errorf("interval = %d, want %d", interval, defaultPluginIntervalSec)
	}
	if timeout != defaultPluginTimeoutSec {
		t.Errorf("timeout = %d, want %d", timeout, defaultPluginTimeoutSec)
	}
}

func TestEffectiveHealthCheck_ZerosFallBackToDefaults(t *testing.T) {
	path, interval, timeout := effectiveHealthCheck(&mcpv1alpha1.PluginHealthCheck{})
	if path != defaultPluginHealthPath || interval != defaultPluginIntervalSec || timeout != defaultPluginTimeoutSec {
		t.Errorf("got (%q,%d,%d), want defaults", path, interval, timeout)
	}
}

func TestEffectiveHealthCheck_OverridesApplied(t *testing.T) {
	path, interval, timeout := effectiveHealthCheck(&mcpv1alpha1.PluginHealthCheck{
		Path:            "/healthz",
		IntervalSeconds: 7,
		TimeoutSeconds:  2,
	})
	if path != "/healthz" || interval != 7 || timeout != 2 {
		t.Errorf("got (%q,%d,%d), want (/healthz,7,2)", path, interval, timeout)
	}
}

func TestComputePluginPhase(t *testing.T) {
	cases := []struct {
		name       string
		serviceURL string
		healthy    bool
		registered bool
		want       mcpv1alpha1.PluginPhase
	}{
		{"empty url is Failed", "", true, true, mcpv1alpha1.PluginPhaseFailed},
		{"healthy is Healthy", "http://x", true, false, mcpv1alpha1.PluginPhaseHealthy},
		{"unhealthy + previously registered is Unhealthy", "http://x", false, true, mcpv1alpha1.PluginPhaseUnhealthy},
		{"unhealthy + never registered is Registered", "http://x", false, false, mcpv1alpha1.PluginPhaseRegistered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computePluginPhase(tc.serviceURL, tc.healthy, tc.registered)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPluginToRegistration_UsesObservedCapsWhenPresent(t *testing.T) {
	now := metav1.Now()
	plugin := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"},
		Spec: mcpv1alpha1.PluginSpec{
			ServiceType: mcpv1alpha1.PluginServiceTypeVirtualMCP,
			ServiceURL:  "http://svc",
			Version:     "1.0",
			Capabilities: []mcpv1alpha1.PluginCapability{
				{Path: "/spec/path", Methods: []string{"GET"}},
			},
		},
	}
	observed := []mcpv1alpha1.PluginCapability{
		{Path: "/observed", Methods: []string{"GET", "POST"}, Description: "discovered"},
	}
	reg := pluginToRegistration(plugin, observed, &now)
	if reg.ServiceID != "p" {
		t.Errorf("ServiceID = %q, want p", reg.ServiceID)
	}
	if reg.ServiceType != plugins.ServiceTypeVirtualMCP {
		t.Errorf("ServiceType = %q, want virtualmcp", reg.ServiceType)
	}
	if reg.ServiceURL != "http://svc" {
		t.Errorf("ServiceURL = %q", reg.ServiceURL)
	}
	if reg.Version != "1.0" {
		t.Errorf("Version = %q", reg.Version)
	}
	if len(reg.Capabilities) != 1 || reg.Capabilities[0].Path != "/observed" {
		t.Errorf("expected ObservedCapabilities to win; got %+v", reg.Capabilities)
	}
	if !reg.RegisteredAt.Equal(now.Time) {
		t.Errorf("RegisteredAt = %v, want %v", reg.RegisteredAt, now.Time)
	}
}

func TestPluginToRegistration_FallsBackToSpecCaps(t *testing.T) {
	plugin := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"},
		Spec: mcpv1alpha1.PluginSpec{
			ServiceType: mcpv1alpha1.PluginServiceTypeSmartAgents,
			ServiceURL:  "http://svc",
			Capabilities: []mcpv1alpha1.PluginCapability{
				{Path: "/v1/*", Methods: []string{"POST"}, Description: "spec entry"},
			},
		},
	}
	reg := pluginToRegistration(plugin, nil, nil)
	if len(reg.Capabilities) != 1 || reg.Capabilities[0].Path != "/v1/*" {
		t.Errorf("expected spec capabilities when observed empty; got %+v", reg.Capabilities)
	}
}

// recordingStore captures Register/Unregister/UpdateHealth calls without
// pulling in pkg/plugins.ServiceManager (which would force a config
// construction). Implements plugins.PluginServiceManager just for the
// methods the reconciler invokes; the rest panic-on-call so a regression
// that calls them shows up loudly.
type recordingStore struct {
	registered   []*plugins.ServiceRegistration
	unregistered []string
	healthUpdate []plugins.ServiceHealth
	regErr       error
}

func (s *recordingStore) RegisterService(reg *plugins.ServiceRegistration) error {
	s.registered = append(s.registered, reg)
	return s.regErr
}
func (s *recordingStore) UnregisterService(id string) error {
	s.unregistered = append(s.unregistered, id)
	return nil
}
func (s *recordingStore) GetService(string) (*plugins.ServiceRegistration, bool) {
	panic("not used")
}
func (s *recordingStore) GetServicesByType(plugins.ServiceType) []*plugins.ServiceRegistration {
	panic("not used")
}
func (s *recordingStore) GetAllServices() []*plugins.ServiceRegistration { panic("not used") }
func (s *recordingStore) IsServiceEnabled(plugins.ServiceType) bool      { panic("not used") }
func (s *recordingStore) UpdateServiceHealth(_ string, h plugins.ServiceHealth) {
	s.healthUpdate = append(s.healthUpdate, h)
}
func (s *recordingStore) GetServiceHealth(string) (plugins.ServiceHealth, bool) { panic("not used") }
func (s *recordingStore) GetServiceForPath(string) (*plugins.ServiceRegistration, bool) {
	panic("not used")
}

func TestProber_NonVirtualMCP_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewProber(srv.Client())
	res := p.Probe(context.Background(), mcpv1alpha1.PluginServiceTypeSmartAgents, srv.URL, "/health", 2*time.Second)
	if !res.Healthy {
		t.Errorf("expected healthy, got %+v", res)
	}
	if res.ResponseTime <= 0 {
		t.Errorf("expected positive ResponseTime, got %v", res.ResponseTime)
	}
}

func TestProber_NonVirtualMCP_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p := NewProber(srv.Client())
	res := p.Probe(context.Background(), mcpv1alpha1.PluginServiceTypeSmartAgents, srv.URL, "/health", 2*time.Second)
	if res.Healthy {
		t.Errorf("expected unhealthy for 503, got %+v", res)
	}
	if res.Message == "" {
		t.Error("expected non-empty failure message")
	}
}

func TestProber_NonVirtualMCP_Unreachable(t *testing.T) {
	p := NewProber(&http.Client{Timeout: 500 * time.Millisecond})
	// Reserved TEST-NET-1 address that won't route — fails fast on dial.
	res := p.Probe(context.Background(), mcpv1alpha1.PluginServiceTypeSmartAgents, "http://192.0.2.1:1", "/health", 200*time.Millisecond)
	if res.Healthy {
		t.Errorf("expected unhealthy for unreachable host, got %+v", res)
	}
}

func TestProber_VirtualMCP_HealthyAndDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/mcps":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"implementations": []map[string]any{
					{"id": "echo", "name": "Echo", "description": "echoes input", "version": "1.2.3"},
					{"id": "math", "name": "Math", "description": "arithmetic"},
				},
				"count":   2,
				"service": "vmcp-1",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := NewProber(srv.Client())

	res := p.Probe(context.Background(), mcpv1alpha1.PluginServiceTypeVirtualMCP, srv.URL, "/health", 2*time.Second)
	if !res.Healthy {
		t.Fatalf("expected healthy, got %+v", res)
	}

	caps, err := p.DiscoverCapabilities(context.Background(), "vmcp-1", srv.URL)
	if err != nil {
		t.Fatalf("DiscoverCapabilities: %v", err)
	}
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d (%+v)", len(caps), caps)
	}
	// IDs are prefixed by the discoverer: <source>-<serviceID>-<id>.
	wantPath := "/api/v1/mcps/virtualmcp-vmcp-1-echo"
	if caps[0].Path != wantPath {
		t.Errorf("caps[0].Path = %q, want %q", caps[0].Path, wantPath)
	}
	if caps[0].Methods[0] != http.MethodGet {
		t.Errorf("caps[0].Methods = %v, want [GET]", caps[0].Methods)
	}
	if caps[0].Description != "echoes input" {
		t.Errorf("caps[0].Description = %q", caps[0].Description)
	}
}

func TestProber_VirtualMCP_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewProber(srv.Client())
	res := p.Probe(context.Background(), mcpv1alpha1.PluginServiceTypeVirtualMCP, srv.URL, "/health", 2*time.Second)
	if res.Healthy {
		t.Errorf("expected unhealthy for 500 on /health, got %+v", res)
	}
}

// fakeProber lets reconciler-level tests skip real HTTP work and assert
// the reconciler's wiring without depending on a controller-runtime fake
// client (none is in use elsewhere in this package).
type fakeProber struct {
	probeResult ProbeResult
	caps        []mcpv1alpha1.PluginCapability
	discoverErr error
	probeCalls  int
	discCalls   int
}

func (f *fakeProber) Probe(_ context.Context, _ mcpv1alpha1.PluginServiceType, _, _ string, _ time.Duration) ProbeResult {
	f.probeCalls++
	return f.probeResult
}
func (f *fakeProber) DiscoverCapabilities(_ context.Context, _, _ string) ([]mcpv1alpha1.PluginCapability, error) {
	f.discCalls++
	return f.caps, f.discoverErr
}

// reflectToStore is the seam reconciler-level wiring tests can exercise
// without a kube client. Validates: (1) registration is projected when
// Store is non-nil, (2) UpdateServiceHealth is called with the right
// status, (3) Store=nil is a no-op (graceful for the early manager
// binary that doesn't share its store with the data plane yet).
func TestReflectToStore_NilStoreIsNoOp(t *testing.T) {
	r := &PluginReconciler{}
	r.reflectToStore(context.Background(),
		&mcpv1alpha1.Plugin{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"}},
		true, nil, nil)
	// No panic, no state. The test passes by virtue of not exploding.
}

func TestReflectToStore_HealthyRegistersAndMarksHealthy(t *testing.T) {
	store := &recordingStore{}
	r := &PluginReconciler{Store: store}
	now := metav1.Now()
	plugin := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"},
		Spec: mcpv1alpha1.PluginSpec{
			ServiceType: mcpv1alpha1.PluginServiceTypeSmartAgents,
			ServiceURL:  "http://svc",
		},
	}
	r.reflectToStore(context.Background(), plugin, true, nil, &now)
	if len(store.registered) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(store.registered))
	}
	if store.registered[0].ServiceID != "p" {
		t.Errorf("ServiceID = %q, want p", store.registered[0].ServiceID)
	}
	if len(store.healthUpdate) != 1 || store.healthUpdate[0].Status != "healthy" {
		t.Errorf("expected healthy update, got %+v", store.healthUpdate)
	}
}

func TestReflectToStore_UnhealthyStillRegisters(t *testing.T) {
	store := &recordingStore{}
	r := &PluginReconciler{Store: store}
	plugin := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"},
		Spec:       mcpv1alpha1.PluginSpec{ServiceURL: "http://svc"},
	}
	r.reflectToStore(context.Background(), plugin, false, nil, nil)
	if len(store.registered) != 1 {
		t.Fatalf("unhealthy should still register; got %d", len(store.registered))
	}
	if store.healthUpdate[0].Status != "unhealthy" {
		t.Errorf("expected unhealthy update, got %q", store.healthUpdate[0].Status)
	}
}

func TestRemoveFromStore_NilStoreIsNoOp(t *testing.T) {
	r := &PluginReconciler{}
	r.removeFromStore(context.Background(), "ns/p") // no panic
}

func TestRemoveFromStore_DelegatesUnregister(t *testing.T) {
	store := &recordingStore{}
	r := &PluginReconciler{Store: store}
	r.removeFromStore(context.Background(), "ns/p")
	if len(store.unregistered) != 1 || store.unregistered[0] != "ns/p" {
		t.Errorf("unregistered = %v", store.unregistered)
	}
}

func TestProberSelector_NilReturnsDefault(t *testing.T) {
	r := &PluginReconciler{}
	if r.prober() == nil {
		t.Error("expected non-nil default prober")
	}
}

func TestProberSelector_HonorsInjected(t *testing.T) {
	fake := &fakeProber{}
	r := &PluginReconciler{Prober: fake}
	if r.prober() != fake {
		t.Error("expected injected prober to be returned")
	}
}

// TestPluginStoreID_DropsNamespacePrefix locks the contract the HTTP
// write-through path (P2.4e) depends on: ServiceManager keys must match
// the raw service_id callers POST to /api/v1/plugins/register, so the
// store ID is just the CR name — no namespace prefix.
func TestPluginStoreID_DropsNamespacePrefix(t *testing.T) {
	if got := pluginStoreID("any-namespace", "myplugin"); got != "myplugin" {
		t.Errorf("pluginStoreID = %q, want \"myplugin\" (HTTP read-path lookup-by-id depends on this)", got)
	}
}
