package services

import (
	"strings"
	"testing"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

func TestGetMapKeys(t *testing.T) {
	if got := getMapKeys(nil); got != nil {
		t.Errorf("nil map should return nil, got %v", got)
	}

	m := map[string]interface{}{"a": 1, "b": 2}
	keys := getMapKeys(m)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("missing keys: %v", keys)
	}
}

func TestSubstituteTemplates(t *testing.T) {
	svc := &AdapterService{}
	envVars := map[string]string{
		"UYUNI_SERVER": "http://uyuni.example.com",
		"UYUNI_USER":   "admin",
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain string", "no templates here", "no templates here"},
		{"single template", "url={{uyuni.server}}", "url=http://uyuni.example.com"},
		{"multiple templates", "{{uyuni.user}}@{{uyuni.server}}", "admin@http://uyuni.example.com"},
		{"unmatched template", "{{missing.var}}", "{{missing.var}}"},
		{"empty input", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.substituteTemplates(tc.input, envVars); got != tc.want {
				t.Errorf("substituteTemplates(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestProcessCommandTemplates_NoTemplatesNoChange(t *testing.T) {
	svc := &AdapterService{}
	cfg := &models.SidecarConfig{CommandType: "docker", Command: "docker run image"}
	server := &models.MCPServer{Meta: map[string]interface{}{}}

	got := svc.processCommandTemplates(cfg, server)
	if got.Command != cfg.Command {
		t.Errorf("command should pass through unchanged, got %q", got.Command)
	}
}

func TestProcessCommandTemplates_EmptyCommand(t *testing.T) {
	svc := &AdapterService{}
	cfg := &models.SidecarConfig{CommandType: "docker", Command: ""}
	got := svc.processCommandTemplates(cfg, &models.MCPServer{})
	if got != cfg {
		t.Error("empty command should return the original config pointer")
	}
}

func TestProcessCommandTemplates_DockerSubstitutesEnvFlag(t *testing.T) {
	svc := &AdapterService{}
	cfg := &models.SidecarConfig{
		CommandType: "docker",
		Command:     "docker run {{api_token}} image",
	}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{
					"name": "api_token",
					"env":  "API_TOKEN",
				},
			},
		},
	}

	got := svc.processCommandTemplates(cfg, server)
	want := "docker run -e API_TOKEN=$API_TOKEN image"
	if got.Command != want {
		t.Errorf("got %q, want %q", got.Command, want)
	}
}

func TestProcessCommandTemplates_GenericSubstitutesEnvRef(t *testing.T) {
	svc := &AdapterService{}
	cfg := &models.SidecarConfig{
		CommandType: "python",
		Command:     "python server.py --token {{api_token}}",
	}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{
					"name": "api_token",
					"env":  "API_TOKEN",
				},
			},
		},
	}

	got := svc.processCommandTemplates(cfg, server)
	want := "python server.py --token $API_TOKEN"
	if got.Command != want {
		t.Errorf("got %q, want %q", got.Command, want)
	}
}

func TestProcessCommandTemplates_UnknownCommandTypePassesThrough(t *testing.T) {
	svc := &AdapterService{}
	cfg := &models.SidecarConfig{
		CommandType: "weird",
		Command:     "weird {{foo}}",
	}
	got := svc.processCommandTemplates(cfg, &models.MCPServer{})
	if got.Command != cfg.Command {
		t.Errorf("unknown command type should leave command unchanged, got %q", got.Command)
	}
}

func TestLookupTemplatedVariable_DirectSecrets(t *testing.T) {
	svc := &AdapterService{}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{
					"name": "token",
					"env":  "MY_TOKEN",
				},
			},
		},
	}

	if got := svc.lookupTemplatedVariable("token", server); got != "MY_TOKEN" {
		t.Errorf("got %q, want %q", got, "MY_TOKEN")
	}
}

func TestLookupTemplatedVariable_NestedConfigSecrets(t *testing.T) {
	svc := &AdapterService{}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"config": map[string]interface{}{
				"secrets": []interface{}{
					map[string]interface{}{
						"name": "token",
						"env":  "MY_TOKEN",
					},
				},
			},
		},
	}

	if got := svc.lookupTemplatedVariable("token", server); got != "MY_TOKEN" {
		t.Errorf("got %q, want %q", got, "MY_TOKEN")
	}
}

func TestLookupTemplatedVariable_MissingReturnsEmpty(t *testing.T) {
	svc := &AdapterService{}

	cases := []*models.MCPServer{
		{Meta: nil},                          // no meta
		{Meta: map[string]interface{}{}},     // no secrets
		{Meta: map[string]interface{}{"secrets": "not-a-slice"}},
		{Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{"name": "other", "env": "OTHER"},
			},
		}}, // no matching name
		{Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{"name": "token"}, // missing env
			},
		}},
	}

	for i, srv := range cases {
		if got := svc.lookupTemplatedVariable("token", srv); got != "" {
			t.Errorf("case %d: expected empty, got %q", i, got)
		}
	}
}

func TestLookupTemplatedVariableGeneric_MatchesSameShapes(t *testing.T) {
	svc := &AdapterService{}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"config": map[string]interface{}{
				"secrets": []interface{}{
					map[string]interface{}{
						"name": "token",
						"env":  "TOKEN_GEN",
					},
				},
			},
		},
	}
	if got := svc.lookupTemplatedVariableGeneric("token", server); got != "TOKEN_GEN" {
		t.Errorf("got %q, want %q", got, "TOKEN_GEN")
	}

	if got := svc.lookupTemplatedVariableGeneric("token", &models.MCPServer{}); got != "" {
		t.Errorf("expected empty for nil meta, got %q", got)
	}
}

func TestProcessTemplatesGeneric_MultipleSecrets(t *testing.T) {
	svc := &AdapterService{}
	server := &models.MCPServer{
		Meta: map[string]interface{}{
			"secrets": []interface{}{
				map[string]interface{}{"name": "user", "env": "MY_USER"},
				map[string]interface{}{"name": "pass", "env": "MY_PASS"},
			},
		},
	}
	cmd := "python server.py --user {{user}} --pass {{pass}}"
	got := svc.processTemplatesGeneric(cmd, server)
	if !strings.Contains(got, "$MY_USER") || !strings.Contains(got, "$MY_PASS") {
		t.Errorf("both substitutions expected, got %q", got)
	}
}
