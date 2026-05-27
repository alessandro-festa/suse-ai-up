package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

func TestDefaultRegistryManager_UploadAndClear(t *testing.T) {
	store := clients.NewInMemoryMCPServerStore()
	rm := NewDefaultRegistryManager(store)

	err := rm.UploadRegistryEntries([]*models.MCPServer{
		{ID: "a", Name: "A"},
		{ID: "b", Name: "B"},
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := len(store.ListMCPServers()); got != 2 {
		t.Errorf("after upload: want 2 servers, got %d", got)
	}

	if err := rm.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := len(store.ListMCPServers()); got != 0 {
		t.Errorf("after clear: want 0 servers, got %d", got)
	}
}

func TestDefaultRegistryManager_UploadDuplicateOverwrites(t *testing.T) {
	// InMemoryMCPServerStore is a map[string]*MCPServer keyed by ID — re-uploading
	// the same ID overwrites silently. Documenting that contract here so a future
	// change to require de-dup will surface as a test failure.
	store := clients.NewInMemoryMCPServerStore()
	rm := NewDefaultRegistryManager(store)

	if err := rm.UploadRegistryEntries([]*models.MCPServer{{ID: "a", Name: "v1"}}); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if err := rm.UploadRegistryEntries([]*models.MCPServer{{ID: "a", Name: "v2"}}); err != nil {
		t.Fatalf("second upload should overwrite silently, got %v", err)
	}
	got, _ := store.GetMCPServer("a")
	if got.Name != "v2" {
		t.Errorf("expected name=v2 after overwrite, got %q", got.Name)
	}
}

func TestDefaultRegistryManager_SearchByQuery(t *testing.T) {
	store := clients.NewInMemoryMCPServerStore()
	rm := NewDefaultRegistryManager(store)
	rm.UploadRegistryEntries([]*models.MCPServer{
		{ID: "uy", Name: "Uyuni", Description: "Patching tool"},
		{ID: "bz", Name: "Bugzilla", Description: "Issue tracker"},
		{ID: "tr", Name: "Trento", Description: "SAP monitoring", Repository: models.Repository{Source: "github"}},
	})

	hits, err := rm.SearchServers("uyuni", nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != "uy" {
		t.Errorf("search uyuni: %+v", hits)
	}

	hits, _ = rm.SearchServers("issue", nil)
	if len(hits) != 1 || hits[0].ID != "bz" {
		t.Errorf("search by description: %+v", hits)
	}

	hits, _ = rm.SearchServers("github", nil)
	if len(hits) != 1 || hits[0].ID != "tr" {
		t.Errorf("search by repository source: %+v", hits)
	}

	hits, _ = rm.SearchServers("nope-no-match", nil)
	if len(hits) != 0 {
		t.Errorf("no-match search returned %+v", hits)
	}
}

func TestDefaultRegistryManager_SearchByFilters(t *testing.T) {
	store := clients.NewInMemoryMCPServerStore()
	rm := NewDefaultRegistryManager(store)
	rm.UploadRegistryEntries([]*models.MCPServer{
		{
			ID: "stdio-srv", Name: "S",
			Packages: []models.Package{{Transport: models.Transport{Type: "stdio"}, RegistryType: "npm"}},
		},
		{
			ID: "http-srv", Name: "H",
			Packages:         []models.Package{{Transport: models.Transport{Type: "http"}, RegistryType: "oci"}},
			ValidationStatus: "validated",
			Meta: map[string]interface{}{
				"source":          "github",
				"registry_source": "yaml",
			},
		},
	})

	cases := []struct {
		name    string
		filters map[string]interface{}
		wantIDs []string
	}{
		{"transport=http", map[string]interface{}{"transport": "http"}, []string{"http-srv"}},
		{"transport=stdio", map[string]interface{}{"transport": "stdio"}, []string{"stdio-srv"}},
		{"registryType=npm", map[string]interface{}{"registryType": "npm"}, []string{"stdio-srv"}},
		{"validationStatus=validated", map[string]interface{}{"validationStatus": "validated"}, []string{"http-srv"}},
		{"source=github", map[string]interface{}{"source": "github"}, []string{"http-srv"}},
		{"registry_source=yaml", map[string]interface{}{"registry_source": "yaml"}, []string{"http-srv"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := rm.SearchServers("", tc.filters)
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("got %d, want %d (%+v)", len(got), len(tc.wantIDs), got)
			}
			for i, want := range tc.wantIDs {
				if got[i].ID != want {
					t.Errorf("[%d] got %q, want %q", i, got[i].ID, want)
				}
			}
		})
	}
}

func TestDefaultRegistryManager_LoadFromCustomSource(t *testing.T) {
	// Stand up an httptest server that returns a JSON list of MCP servers.
	servers := []*models.MCPServer{{ID: "remote-1", Name: "Remote"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(servers)
	}))
	t.Cleanup(srv.Close)

	store := clients.NewInMemoryMCPServerStore()
	rm := NewDefaultRegistryManager(store)

	if err := rm.LoadFromCustomSource(srv.URL); err != nil {
		t.Fatalf("load: %v", err)
	}
	got, _ := store.GetMCPServer("remote-1")
	if got == nil || got.Name != "Remote" {
		t.Errorf("expected remote-1 loaded into store, got %+v", got)
	}
}

func TestDefaultRegistryManager_LoadFromCustomSource_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	rm := NewDefaultRegistryManager(clients.NewInMemoryMCPServerStore())
	if err := rm.LoadFromCustomSource(srv.URL); err == nil {
		t.Error("expected error from 500 response")
	}
}

func TestDefaultRegistryManager_LoadFromCustomSource_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	rm := NewDefaultRegistryManager(clients.NewInMemoryMCPServerStore())
	if err := rm.LoadFromCustomSource(srv.URL); err == nil {
		t.Error("expected error from invalid JSON")
	}
}
