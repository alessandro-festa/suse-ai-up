package proxy

import (
	"context"
	"os"
	"strings"
	"testing"

	"suse-ai-up/pkg/models"
)

func TestGetSidecarEndpoint(t *testing.T) {
	sm := &SidecarManager{namespace: "suse-ai-up-mcp"}
	got := sm.GetSidecarEndpoint("my-adapter")
	want := "http://mcp-sidecar-my-adapter.suse-ai-up-mcp.svc.cluster.local"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGetImageForCommandType(t *testing.T) {
	sm := &SidecarManager{}
	tests := []struct {
		commandType string
		wantPrefix  string
	}{
		{"python", "registry.suse.com/bci/python"},
		{"npx", "registry.suse.com/bci/nodejs"},
		{"go", "registry.suse.com/bci/golang"},
		{"unknown-type", "python:3.11-slim"},
		{"", "python:3.11-slim"},
	}
	for _, tc := range tests {
		t.Run(tc.commandType, func(t *testing.T) {
			got := sm.getImageForCommandType(tc.commandType)
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("commandType %q: got %q, want prefix %q", tc.commandType, got, tc.wantPrefix)
			}
		})
	}
}

func TestBuildEnvVarsWithOverrides_AppendsUvicornHost(t *testing.T) {
	sm := &SidecarManager{}
	envs := sm.buildEnvVarsWithOverrides(map[string]string{"FOO": "bar"})

	foundFoo, foundUvicorn := false, false
	for _, e := range envs {
		if e.Name == "FOO" && e.Value == "bar" {
			foundFoo = true
		}
		if e.Name == "UVICORN_HOST" && e.Value == "0.0.0.0" {
			foundUvicorn = true
		}
	}
	if !foundFoo {
		t.Error("expected FOO=bar in env vars")
	}
	if !foundUvicorn {
		t.Error("expected UVICORN_HOST=0.0.0.0 auto-appended")
	}
}

func TestBuildEnvVarsWithOverrides_EmptyMap(t *testing.T) {
	sm := &SidecarManager{}
	envs := sm.buildEnvVarsWithOverrides(nil)
	if len(envs) != 1 || envs[0].Name != "UVICORN_HOST" {
		t.Errorf("expected only UVICORN_HOST, got %+v", envs)
	}
}

func TestIsInCluster(t *testing.T) {
	// Snapshot and restore env so the test is hermetic.
	origHost, hadHost := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	origPort, hadPort := os.LookupEnv("KUBERNETES_SERVICE_PORT")
	t.Cleanup(func() {
		if hadHost {
			os.Setenv("KUBERNETES_SERVICE_HOST", origHost)
		} else {
			os.Unsetenv("KUBERNETES_SERVICE_HOST")
		}
		if hadPort {
			os.Setenv("KUBERNETES_SERVICE_PORT", origPort)
		} else {
			os.Unsetenv("KUBERNETES_SERVICE_PORT")
		}
	})

	sm := &SidecarManager{}

	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")
	if sm.isInCluster() {
		t.Error("isInCluster should be false when env vars missing")
	}

	os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	os.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if !sm.isInCluster() {
		t.Error("isInCluster should be true when both env vars set")
	}
}

func TestDeploySidecar_HTTPIsNoop(t *testing.T) {
	// HTTP command type means "remote MCP server, no sidecar deployment".
	sm := &SidecarManager{} // no kubeClient, no dockerDeployer needed for this path
	adapter := models.AdapterResource{
		AdapterData: models.AdapterData{
			SidecarConfig: &models.SidecarConfig{CommandType: "http"},
		},
		ID: "remote-1",
	}
	// Make sure we're not flagged as in-cluster.
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	if err := sm.DeploySidecar(context.Background(), adapter); err != nil {
		t.Errorf("http commandType should be a no-op, got error: %v", err)
	}
}

func TestDeploySidecar_UnsupportedCommandTypeErrors(t *testing.T) {
	sm := &SidecarManager{}
	adapter := models.AdapterResource{
		AdapterData: models.AdapterData{
			SidecarConfig: &models.SidecarConfig{CommandType: "rust"},
		},
		ID: "rust-1",
	}
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	err := sm.DeploySidecar(context.Background(), adapter)
	if err == nil {
		t.Fatal("expected unsupported commandType to error")
	}
	if !strings.Contains(err.Error(), "unsupported sidecar configuration") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDeploySidecar_EmptyCommandErrors(t *testing.T) {
	sm := &SidecarManager{}
	adapter := models.AdapterResource{
		AdapterData: models.AdapterData{
			SidecarConfig: &models.SidecarConfig{CommandType: "python", Command: ""},
		},
		ID: "py-1",
	}
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	err := sm.DeploySidecar(context.Background(), adapter)
	if err == nil {
		t.Fatal("expected empty command to error")
	}
	if !strings.Contains(err.Error(), "empty command") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetStatus_NoKubeClient(t *testing.T) {
	sm := &SidecarManager{}
	st, err := sm.GetStatus(context.Background(), "any")
	if err != nil {
		t.Fatalf("status with no client should not error, got %v", err)
	}
	if st.ReplicaStatus != "unknown (no k8s client)" {
		t.Errorf("got %q, want 'unknown (no k8s client)'", st.ReplicaStatus)
	}
}

func TestPortManager_AllocateAndRelease(t *testing.T) {
	pm := NewPortManager(8000, 8002)

	// First allocation gets the lowest free port.
	p1, err := pm.AllocatePort("a")
	if err != nil {
		t.Fatalf("allocate a: %v", err)
	}
	if p1 != 8000 {
		t.Errorf("a got port %d, want 8000", p1)
	}

	// Same adapter is idempotent.
	again, err := pm.AllocatePort("a")
	if err != nil || again != p1 {
		t.Errorf("re-allocate should return same port, got (%d, %v)", again, err)
	}

	p2, _ := pm.AllocatePort("b")
	p3, _ := pm.AllocatePort("c")
	if p2 == p1 || p3 == p1 || p2 == p3 {
		t.Errorf("ports should be distinct, got %d/%d/%d", p1, p2, p3)
	}

	// Range is exhausted.
	if _, err := pm.AllocatePort("d"); err == nil {
		t.Error("expected exhausted range to error")
	}

	// Release frees the port for someone new.
	pm.ReleasePort("a")
	p4, err := pm.AllocatePort("d")
	if err != nil {
		t.Fatalf("after release, allocate d: %v", err)
	}
	if p4 != p1 {
		t.Errorf("d should get freed port %d, got %d", p1, p4)
	}
}

func TestPortManager_GetAllocatedPort(t *testing.T) {
	pm := NewPortManager(9000, 9100)
	if _, ok := pm.GetAllocatedPort("missing"); ok {
		t.Error("missing adapter should report not allocated")
	}
	port, _ := pm.AllocatePort("x")
	got, ok := pm.GetAllocatedPort("x")
	if !ok || got != port {
		t.Errorf("got (%d, %v), want (%d, true)", got, ok, port)
	}
}
