package handlers

import (
	"strings"
	"testing"

	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/services/virtualmcp"
)

func TestGenerateAdapterName(t *testing.T) {
	h := &RegistrationHandler{}
	tests := []struct {
		name   string
		server *models.DiscoveredServer
		want   string
	}{
		{
			"uses server name lowercased and dash-joined",
			&models.DiscoveredServer{Name: "My Cool Server"},
			"my-cool-server",
		},
		{
			// Address splits on ":" leaving "//host" in parts[1] — the production
			// code preserves the "//" prefix in the generated name.
			"ignores 'Unknown MCP Server' placeholder and falls back to address",
			&models.DiscoveredServer{
				Name:    "Unknown MCP Server",
				ID:      "fallback-id",
				Address: "http://example.com:8080",
			},
			"//example-com-8080",
		},
		{
			"falls back to host-port when only address is meaningful",
			&models.DiscoveredServer{Address: "http://10.0.0.1:9000"},
			"//10-0-0-1-9000",
		},
		{
			"falls back to ID when address is unparseable",
			&models.DiscoveredServer{ID: "just-id", Address: "no-colons"},
			"just-id",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.generateAdapterName(tc.server); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	h := &RegistrationHandler{}

	t1 := h.generateSecureToken()
	t2 := h.generateSecureToken()

	if t1 == "" || t2 == "" {
		t.Fatal("token must be non-empty")
	}
	if t1 == t2 {
		t.Error("two successive tokens should differ")
	}
	// base64-URL encoding of 32 bytes is 43 chars + 1 '=' pad = 44.
	if len(t1) < 40 {
		t.Errorf("token suspiciously short: %d chars", len(t1))
	}
}

func TestGetSecurityNote(t *testing.T) {
	h := &RegistrationHandler{}
	tests := []struct {
		score string
		want  string
	}{
		{"high", "no authentication"},
		{"medium", "optional authentication"},
		{"low", "additional security layer"},
		{"unknown", "conservative security"},
		{"", "conservative security"},
	}
	for _, tc := range tests {
		t.Run(tc.score, func(t *testing.T) {
			got := h.getSecurityNote(&models.DiscoveredServer{VulnerabilityScore: tc.score})
			if !strings.Contains(got, tc.want) {
				t.Errorf("score %q: note %q missing substring %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestCreateAdapterDataFromDiscovered_VirtualMCP(t *testing.T) {
	h := &RegistrationHandler{}
	server := &models.DiscoveredServer{
		Name:    "vmcp",
		Address: "http://vmcp.svc:8000",
		Metadata: map[string]string{
			"source": virtualmcp.SourceLabel,
		},
	}
	data := h.createAdapterDataFromDiscovered(server)
	if data.ConnectionType != models.ConnectionTypeStreamableHttp {
		t.Errorf("want streamable_http, got %q", data.ConnectionType)
	}
	if data.RemoteUrl != "http://vmcp.svc:8000" {
		t.Errorf("RemoteUrl not propagated: %q", data.RemoteUrl)
	}
	if !strings.Contains(data.Description, "VirtualMCP") {
		t.Errorf("description should mark as VirtualMCP, got %q", data.Description)
	}
}

func TestCreateAdapterDataFromDiscovered_RegularServer(t *testing.T) {
	h := &RegistrationHandler{}
	server := &models.DiscoveredServer{
		Name:       "regular",
		Address:    "http://srv.local:9000",
		Connection: models.ConnectionTypeRemoteHttp,
		Metadata: map[string]string{
			"auth_type": "bearer",
		},
	}
	data := h.createAdapterDataFromDiscovered(server)
	if data.ConnectionType != models.ConnectionTypeRemoteHttp {
		t.Errorf("connection type should propagate, got %q", data.ConnectionType)
	}
	if data.EnvironmentVariables["MCP_PROXY_URL"] != "http://srv.local:9000" {
		t.Errorf("MCP_PROXY_URL not set: %+v", data.EnvironmentVariables)
	}
	if data.EnvironmentVariables["MCP_SERVER_AUTH_TYPE"] != "bearer" {
		t.Errorf("auth_type not propagated: %+v", data.EnvironmentVariables)
	}
	if data.ImageName != "mcp-proxy" {
		t.Errorf("expected mcp-proxy image, got %q", data.ImageName)
	}
}

func TestConfigureAuthentication_FallbackPath(t *testing.T) {
	// tokenManager nil → falls back to local token generation.
	h := &RegistrationHandler{}

	cases := []struct {
		score       string
		wantBackend string
	}{
		{"high", "false"},
		{"low", "true"},
		{"unknown", "true"},
	}
	for _, tc := range cases {
		t.Run(tc.score, func(t *testing.T) {
			ad := &models.AdapterData{
				Name:                 "a-" + tc.score,
				EnvironmentVariables: map[string]string{},
			}
			info, err := h.configureAuthentication(&models.DiscoveredServer{VulnerabilityScore: tc.score}, ad)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info == nil || info.AccessToken == "" {
				t.Fatalf("token info missing: %+v", info)
			}
			if ad.Authentication == nil || !ad.Authentication.Required || ad.Authentication.Type != "bearer" {
				t.Errorf("auth not configured: %+v", ad.Authentication)
			}
			if ad.EnvironmentVariables["MCP_BACKEND_AUTH_REQUIRED"] != tc.wantBackend {
				t.Errorf("score %q: backend auth flag = %q, want %q",
					tc.score, ad.EnvironmentVariables["MCP_BACKEND_AUTH_REQUIRED"], tc.wantBackend)
			}
		})
	}
}
