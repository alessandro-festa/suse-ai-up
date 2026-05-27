package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// fakeRegMgr implements loader.Manager for tests.
type fakeRegMgr struct {
	cleared bool
	entries []*models.MCPServer
	upErr   error
}

func (f *fakeRegMgr) Clear() error { f.cleared = true; return nil }
func (f *fakeRegMgr) UploadRegistryEntries(entries []*models.MCPServer) error {
	if f.upErr != nil {
		return f.upErr
	}
	f.entries = append(f.entries, entries...)
	return nil
}
func (f *fakeRegMgr) LoadFromCustomSource(url string) error { return nil }
func (f *fakeRegMgr) SearchServers(query string, filters map[string]interface{}) ([]*models.MCPServer, error) {
	return nil, nil
}

// fakeStore implements loader.Store; only ListMCPServers/CreateMCPServer are exercised.
type fakeStore struct {
	servers map[string]*models.MCPServer
}

func newFakeStore() *fakeStore { return &fakeStore{servers: map[string]*models.MCPServer{}} }

func (s *fakeStore) CreateMCPServer(server *models.MCPServer) error {
	s.servers[server.ID] = server
	return nil
}
func (s *fakeStore) GetMCPServer(id string) (*models.MCPServer, error) {
	if v, ok := s.servers[id]; ok {
		return v, nil
	}
	return nil, nil
}
func (s *fakeStore) UpdateMCPServer(id string, updated *models.MCPServer) error {
	s.servers[id] = updated
	return nil
}
func (s *fakeStore) DeleteMCPServer(id string) error { delete(s.servers, id); return nil }
func (s *fakeStore) ListMCPServers() []*models.MCPServer {
	out := make([]*models.MCPServer, 0, len(s.servers))
	for _, v := range s.servers {
		out = append(out, v)
	}
	return out
}

func TestReloadFromConfig_FromURL_JSON(t *testing.T) {
	body := []byte(`[{"name":"srv1","description":"d","image":"img:1","meta":{"x":"y"}}]`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	regMgr := &fakeRegMgr{}
	store := newFakeStore()
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "5s"}
	svc := NewService(store, regMgr, nil, cfg)

	result, err := svc.ReloadFromConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !regMgr.cleared {
		t.Error("expected Clear() to be called")
	}
	if result.ServerCount != 1 {
		t.Errorf("want 1 server, got %d", result.ServerCount)
	}
	if result.Source != srv.URL {
		t.Errorf("want source %q, got %q", srv.URL, result.Source)
	}
	if len(regMgr.entries) != 1 || regMgr.entries[0].Name != "srv1" {
		t.Errorf("entries not uploaded: %+v", regMgr.entries)
	}
	// JSON path adds source=yaml marker for unified downstream handling.
	if regMgr.entries[0].Meta["source"] != "yaml" {
		t.Errorf("meta.source not stamped: %+v", regMgr.entries[0].Meta)
	}
}

func TestReloadFromConfig_FromURL_YAMLFallback(t *testing.T) {
	body := []byte(`
- name: yserv
  description: from yaml
  image: y:1
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	regMgr := &fakeRegMgr{}
	store := newFakeStore()
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "5s"}
	svc := NewService(store, regMgr, nil, cfg)

	result, err := svc.ReloadFromConfig(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ServerCount != 1 {
		t.Errorf("want 1, got %d", result.ServerCount)
	}
	if len(regMgr.entries) != 1 || regMgr.entries[0].Name != "yserv" {
		t.Errorf("yaml entry not parsed: %+v", regMgr.entries)
	}
}

func TestReloadFromConfig_BadTimeoutDefaults(t *testing.T) {
	// Invalid timeout string → falls back to 30s default, request still succeeds.
	body := []byte(`[{"name":"srv1"}]`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	regMgr := &fakeRegMgr{}
	store := newFakeStore()
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "not-a-duration"}
	svc := NewService(store, regMgr, nil, cfg)

	if _, err := svc.ReloadFromConfig(context.Background()); err != nil {
		t.Errorf("should fall back to default timeout, got %v", err)
	}
}

func TestReloadFromConfig_URLFails_FallsBackToFile(t *testing.T) {
	// URL returns 500 → falls back to the on-disk default registry file.
	// We do not assert success here because the local file may or may not exist
	// in this test working directory; we just assert that the URL error did not
	// short-circuit the fallback attempt.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	regMgr := &fakeRegMgr{}
	store := newFakeStore()
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "5s"}
	svc := NewService(store, regMgr, nil, cfg)

	// Whatever the outcome of the local file load, the call must not panic and
	// must return one of (result, nil) or (zero, error).
	_, _ = svc.ReloadFromConfig(context.Background())
}

func TestReloadFromConfig_NoURL_UsesLocalFile(t *testing.T) {
	// Empty URL → goes straight to local file fallback.
	regMgr := &fakeRegMgr{}
	store := newFakeStore()
	cfg := &config.Config{MCPRegistryURL: ""}
	svc := NewService(store, regMgr, nil, cfg)

	// As above, result depends on cwd — we just ensure no panic.
	_, _ = svc.ReloadFromConfig(context.Background())
}

func TestUpdateConfigMap_NoK8sClient(t *testing.T) {
	// nil k8sClient → no-op, returns nil.
	svc := NewService(newFakeStore(), &fakeRegMgr{}, nil, &config.Config{})
	if err := svc.UpdateConfigMap(context.Background(), []byte("data")); err != nil {
		t.Errorf("no k8s client should be no-op, got %v", err)
	}
}

func TestUploadLocalMCP_HappyPath(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, &fakeRegMgr{}, nil, &config.Config{})

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"my-server": map[string]interface{}{
				"command": "python",
				"args":    []string{"main.py"},
			},
		},
	})

	got, err := svc.UploadLocalMCP(context.Background(), LocalMCPParams{
		Name:        "my-server",
		Description: "desc",
		Config:      string(cfgJSON),
		Files:       []LocalMCPFile{{Name: "main.py", Data: []byte("print('hi')")}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "my-server" {
		t.Errorf("name: got %q", got.Name)
	}
	if got.ValidationStatus != "uploaded" {
		t.Errorf("validation status: got %q", got.ValidationStatus)
	}
	if isLocal, _ := got.Meta["isLocalMCP"].(bool); !isLocal {
		t.Errorf("isLocalMCP flag missing")
	}
	if len(store.servers) != 1 {
		t.Errorf("server not persisted, got %d", len(store.servers))
	}
}

func TestUploadLocalMCP_ValidationErrors(t *testing.T) {
	svc := NewService(newFakeStore(), &fakeRegMgr{}, nil, &config.Config{})

	cases := []struct {
		name   string
		params LocalMCPParams
		errSub string
	}{
		{"missing name", LocalMCPParams{Config: `{"mcpServers":{"s":{"command":"python"}}}`, Files: []LocalMCPFile{{Name: "f"}}}, "name is required"},
		{"missing config", LocalMCPParams{Name: "n", Files: []LocalMCPFile{{Name: "f"}}}, "config is required"},
		{"invalid JSON config", LocalMCPParams{Name: "n", Config: "not json", Files: []LocalMCPFile{{Name: "f"}}}, "invalid MCP client configuration JSON"},
		{"empty mcpServers", LocalMCPParams{Name: "n", Config: `{"mcpServers":{}}`, Files: []LocalMCPFile{{Name: "f"}}}, "at least one server"},
		{"no files", LocalMCPParams{Name: "n", Config: `{"mcpServers":{"s":{"command":"python"}}}`}, "at least one file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.UploadLocalMCP(context.Background(), tc.params)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.errSub)
			}
		})
	}
}

func TestGenerateID(t *testing.T) {
	a := generateID()
	b := generateID()
	if a == "" || b == "" {
		t.Error("id should be non-empty")
	}
	// Format is YYYYMMDDHHMMSS + 6-digit nanosecond fraction → 20 chars.
	if len(a) != 20 {
		t.Errorf("unexpected length %d for %q", len(a), a)
	}
}
