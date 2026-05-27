package services

import (
	"strings"
	"testing"

	"suse-ai-up/pkg/models"
)

func TestParseTrentoConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantURL   string
		wantToken string
		wantErr   string
	}{
		{
			name:      "happy path",
			input:     "TRENTO_URL=https://trento.example.com,TOKEN=abc123",
			wantURL:   "https://trento.example.com",
			wantToken: "abc123",
		},
		{
			name:      "tolerates whitespace around parts",
			input:     "TRENTO_URL=https://t.example.com , TOKEN=xyz",
			wantURL:   "https://t.example.com",
			wantToken: "xyz",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "cannot be empty",
		},
		{
			name:    "wrong number of parts",
			input:   "TRENTO_URL=https://x.com",
			wantErr: "invalid TRENTO_CONFIG format",
		},
		{
			name:    "missing TRENTO_URL",
			input:   "OTHER=foo,TOKEN=bar",
			wantErr: "TRENTO_URL not found",
		},
		{
			name:    "missing TOKEN",
			input:   "TRENTO_URL=https://x.com,OTHER=foo",
			wantErr: "TOKEN not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url, token, err := ParseTrentoConfig(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q missing %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if url != tc.wantURL {
				t.Errorf("url = %q, want %q", url, tc.wantURL)
			}
			if token != tc.wantToken {
				t.Errorf("token = %q, want %q", token, tc.wantToken)
			}
		})
	}
}

func TestBuildCreateClientConfig_RemoteHttp(t *testing.T) {
	adapter := &models.AdapterResource{
		AdapterData: models.AdapterData{
			ConnectionType: models.ConnectionTypeRemoteHttp,
			RemoteUrl:      "https://remote.example.com",
		},
		ID: "my-adapter",
	}

	cfg := BuildCreateClientConfig(adapter)

	gemini, ok := cfg["gemini"].(map[string]interface{})
	if !ok {
		t.Fatalf("gemini block missing or wrong type: %+v", cfg["gemini"])
	}
	servers, ok := gemini["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("gemini.mcpServers missing")
	}
	entry, ok := servers["my-adapter"].(map[string]interface{})
	if !ok {
		t.Fatalf("entry for adapter missing")
	}
	if entry["url"] != "https://remote.example.com" {
		t.Errorf("expected upstream url to flow through, got %v", entry["url"])
	}
}

func TestBuildCreateClientConfig_StreamableHttp(t *testing.T) {
	adapter := &models.AdapterResource{
		AdapterData: models.AdapterData{
			ConnectionType: models.ConnectionTypeStreamableHttp,
		},
		ID: "my-adapter",
	}

	cfg := BuildCreateClientConfig(adapter)
	gemini := cfg["gemini"].(map[string]interface{})
	servers := gemini["mcpServers"].(map[string]interface{})
	entry := servers["my-adapter"].(map[string]interface{})

	want := "http://localhost:8911/api/v1/adapters/my-adapter/mcp"
	if entry["httpUrl"] != want {
		t.Errorf("got httpUrl %q, want %q", entry["httpUrl"], want)
	}
}

func TestBuildCreateClientConfig_StdioFallback(t *testing.T) {
	adapter := &models.AdapterResource{
		AdapterData: models.AdapterData{ConnectionType: models.ConnectionTypeLocalStdio},
		ID:          "x",
	}
	cfg := BuildCreateClientConfig(adapter)
	if cfg["stdio"] != "format" {
		t.Errorf("expected stdio fallback shape, got %+v", cfg)
	}
}

func TestBuildListClientConfig_UsesAdapterURL(t *testing.T) {
	adapter := &models.AdapterResource{
		AdapterData: models.AdapterData{URL: "http://localhost:8911/api/v1/adapters/foo/mcp"},
		ID:          "foo",
	}
	cfg := BuildListClientConfig(adapter)
	gemini := cfg["gemini"].(map[string]interface{})
	servers := gemini["mcpServers"].(map[string]interface{})
	entry := servers["foo"].(map[string]interface{})
	if entry["httpUrl"] != adapter.URL {
		t.Errorf("got %v, want %q", entry["httpUrl"], adapter.URL)
	}
}
