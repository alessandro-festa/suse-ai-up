package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/models"
)

// fakeRegistryManager is a stand-in for RegistryManagerInterface that records
// what handler code asked of it and can be set up to fail on demand.
type fakeRegistryManager struct {
	uploadedEntries []*models.MCPServer
	uploadErr       error
	loadCalledWith  string
	loadErr         error
	clearCalled     bool
	searchHits      []*models.MCPServer
}

func (f *fakeRegistryManager) UploadRegistryEntries(entries []*models.MCPServer) error {
	if f.uploadErr != nil {
		return f.uploadErr
	}
	f.uploadedEntries = append(f.uploadedEntries, entries...)
	return nil
}

func (f *fakeRegistryManager) LoadFromCustomSource(sourceURL string) error {
	f.loadCalledWith = sourceURL
	return f.loadErr
}

func (f *fakeRegistryManager) SearchServers(query string, filters map[string]interface{}) ([]*models.MCPServer, error) {
	return f.searchHits, nil
}

func (f *fakeRegistryManager) Clear() error {
	f.clearCalled = true
	return nil
}

// newRegistryHandlerForTest wires up a handler with in-memory store and the
// supplied (optional) fake registry manager. Use only the fields needed by the
// route under test; the rest stay nil.
func newRegistryHandlerForTest(rm RegistryManagerInterface) (*RegistryHandler, MCPServerStore) {
	store := clients.NewInMemoryMCPServerStore()
	h := &RegistryHandler{
		Store:           store,
		RegistryManager: rm,
	}
	return h, store
}

func init() {
	gin.SetMode(gin.TestMode)
}

func TestDetectServerType(t *testing.T) {
	tests := []struct {
		name string
		in   *models.MCPServer
		want ServerType
	}{
		{
			name: "github config marks as github",
			in:   &models.MCPServer{GitHubConfig: &models.GitHubConfig{Token: "t"}},
			want: ServerTypeGitHub,
		},
		{
			name: "meta source=github marks as github",
			in:   &models.MCPServer{Meta: map[string]interface{}{"source": "github"}},
			want: ServerTypeGitHub,
		},
		{
			name: "meta source=stdio marks as localstdio",
			in:   &models.MCPServer{Meta: map[string]interface{}{"source": "stdio"}},
			want: ServerTypeLocalStdio,
		},
		{
			name: "meta source=remote marks as remotehttp",
			in:   &models.MCPServer{Meta: map[string]interface{}{"source": "remote"}},
			want: ServerTypeRemoteHTTP,
		},
		{
			name: "package transport=stdio marks as localstdio",
			in: &models.MCPServer{Packages: []models.Package{
				{Transport: models.Transport{Type: "stdio"}},
			}},
			want: ServerTypeLocalStdio,
		},
		{
			name: "package transport=http marks as remotehttp",
			in: &models.MCPServer{Packages: []models.Package{
				{Transport: models.Transport{Type: "http"}},
			}},
			want: ServerTypeRemoteHTTP,
		},
		{
			name: "URL-only falls through to remotehttp",
			in:   &models.MCPServer{URL: "https://example.com"},
			want: ServerTypeRemoteHTTP,
		},
		{
			name: "no signals defaults to localstdio",
			in:   &models.MCPServer{},
			want: ServerTypeLocalStdio,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectServerType(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetMCPServer_Found(t *testing.T) {
	h, store := newRegistryHandlerForTest(nil)
	store.CreateMCPServer(&models.MCPServer{ID: "s1", Name: "Server 1"})

	router := gin.New()
	router.GET("/registry/:id", h.GetMCPServer)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/registry/s1", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got models.MCPServer
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "s1" {
		t.Errorf("got id %q, want s1", got.ID)
	}
}

func TestGetMCPServer_NotFound(t *testing.T) {
	h, _ := newRegistryHandlerForTest(nil)
	router := gin.New()
	router.GET("/registry/:id", h.GetMCPServer)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/registry/missing", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUpdateMCPServer_PersistsUpdate(t *testing.T) {
	h, store := newRegistryHandlerForTest(nil)
	store.CreateMCPServer(&models.MCPServer{ID: "s1", Name: "old"})

	router := gin.New()
	router.PUT("/registry/:id", h.UpdateMCPServer)

	body, _ := json.Marshal(models.MCPServer{ID: "s1", Name: "new"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/registry/s1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, _ := store.GetMCPServer("s1")
	if got.Name != "new" {
		t.Errorf("name not persisted, got %q", got.Name)
	}
}

func TestUpdateMCPServer_BadJSON(t *testing.T) {
	h, _ := newRegistryHandlerForTest(nil)
	router := gin.New()
	router.PUT("/registry/:id", h.UpdateMCPServer)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/registry/s1", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUpdateMCPServer_MissingReturns404(t *testing.T) {
	h, _ := newRegistryHandlerForTest(nil)
	router := gin.New()
	router.PUT("/registry/:id", h.UpdateMCPServer)

	body, _ := json.Marshal(models.MCPServer{ID: "ghost", Name: "x"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/registry/ghost", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestDeleteMCPServer_RemovesFromStore(t *testing.T) {
	h, store := newRegistryHandlerForTest(nil)
	store.CreateMCPServer(&models.MCPServer{ID: "s1", Name: "x"})

	router := gin.New()
	router.DELETE("/registry/:id", h.DeleteMCPServer)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/registry/s1", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if _, err := store.GetMCPServer("s1"); err == nil {
		t.Error("server should have been deleted")
	}
}

func TestDeleteMCPServer_NotFound(t *testing.T) {
	h, _ := newRegistryHandlerForTest(nil)
	router := gin.New()
	router.DELETE("/registry/:id", h.DeleteMCPServer)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/registry/ghost", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestBrowseRegistry_QueryAndTransportFilters(t *testing.T) {
	h, store := newRegistryHandlerForTest(nil)
	store.CreateMCPServer(&models.MCPServer{
		ID: "uyuni", Name: "Uyuni MCP", Description: "Uyuni stuff",
		Packages: []models.Package{{Transport: models.Transport{Type: "stdio"}}},
	})
	store.CreateMCPServer(&models.MCPServer{
		ID: "bugzilla", Name: "Bugzilla MCP", Description: "Bugzilla stuff",
		Packages: []models.Package{{Transport: models.Transport{Type: "http"}}},
	})

	router := gin.New()
	router.GET("/registry/browse", h.BrowseRegistry)

	cases := []struct {
		name      string
		path      string
		wantCount int
		wantID    string
	}{
		{"no filter returns all", "/registry/browse", 2, ""},
		{"query matches uyuni only", "/registry/browse?q=uyuni", 1, "uyuni"},
		{"transport=http matches bugzilla", "/registry/browse?transport=http", 1, "bugzilla"},
		{"transport=stdio matches uyuni", "/registry/browse?transport=stdio", 1, "uyuni"},
		{"query with no matches", "/registry/browse?q=zzz-nope", 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			var got []*models.MCPServer
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Fatalf("got %d servers, want %d (%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantID != "" && got[0].ID != tc.wantID {
				t.Errorf("got id %q, want %q", got[0].ID, tc.wantID)
			}
		})
	}
}

func TestUploadRegistryEntry_RequiresName(t *testing.T) {
	rm := &fakeRegistryManager{}
	h, _ := newRegistryHandlerForTest(rm)
	router := gin.New()
	router.POST("/registry/upload", h.UploadRegistryEntry)

	body, _ := json.Marshal(models.MCPServer{ID: "x"}) // no name
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registry/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(rm.uploadedEntries) != 0 {
		t.Errorf("nothing should have been uploaded, got %d entries", len(rm.uploadedEntries))
	}
}

func TestUploadRegistryEntry_GeneratesIDWhenMissing(t *testing.T) {
	rm := &fakeRegistryManager{}
	h, _ := newRegistryHandlerForTest(rm)
	router := gin.New()
	router.POST("/registry/upload", h.UploadRegistryEntry)

	body, _ := json.Marshal(models.MCPServer{Name: "needs-id"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registry/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(rm.uploadedEntries) != 1 {
		t.Fatalf("want 1 uploaded entry, got %d", len(rm.uploadedEntries))
	}
	if rm.uploadedEntries[0].ID == "" {
		t.Error("ID should have been generated")
	}
}

func TestUploadRegistryEntry_ManagerError(t *testing.T) {
	rm := &fakeRegistryManager{uploadErr: errors.New("backend exploded")}
	h, _ := newRegistryHandlerForTest(rm)
	router := gin.New()
	router.POST("/registry/upload", h.UploadRegistryEntry)

	body, _ := json.Marshal(models.MCPServer{Name: "x", ID: "id"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registry/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestUploadBulkRegistryEntries_FillsMissingIDs(t *testing.T) {
	rm := &fakeRegistryManager{}
	h, _ := newRegistryHandlerForTest(rm)
	router := gin.New()
	router.POST("/registry/upload/bulk", h.UploadBulkRegistryEntries)

	body, _ := json.Marshal([]*models.MCPServer{
		{Name: "a"},
		{ID: "preset", Name: "b"},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registry/upload/bulk", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(rm.uploadedEntries) != 2 {
		t.Fatalf("want 2 uploaded, got %d", len(rm.uploadedEntries))
	}
	for _, e := range rm.uploadedEntries {
		if e.ID == "" {
			t.Errorf("entry %q has empty ID", e.Name)
		}
	}
}

func TestIsValidMCPFile(t *testing.T) {
	cases := map[string]bool{
		"script.py":         true,
		"requirements.txt":  true,
		"README.md":         true,
		"config.json":       true,
		"malware.exe":       false,
		"image.png":         false,
		"":                  false,
		"script.PY":         false, // case-sensitive by current impl
		"noextension":       false,
	}
	for name, want := range cases {
		if got := isValidMCPFile(name); got != want {
			t.Errorf("isValidMCPFile(%q) = %v, want %v", name, got, want)
		}
	}
}
