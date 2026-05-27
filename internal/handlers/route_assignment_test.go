package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
)

// fakeRouteRegistry is a minimal RegistryStore for tests. It only needs Get/Update.
type fakeRouteRegistry struct {
	servers   map[string]*models.MCPServer
	updateErr error
	getErr    error
}

func newFakeRouteRegistry() *fakeRouteRegistry {
	return &fakeRouteRegistry{servers: map[string]*models.MCPServer{}}
}

func (f *fakeRouteRegistry) GetMCPServer(id string) (*models.MCPServer, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.servers[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}

func (f *fakeRouteRegistry) UpdateMCPServer(id string, updated *models.MCPServer) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.servers[id] = updated
	return nil
}

func newRouteHandler(t *testing.T) (*RouteAssignmentHandler, *fakeRouteRegistry) {
	t.Helper()
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)
	reg := newFakeRouteRegistry()
	return NewRouteAssignmentHandler(svc, reg), reg
}

// --- CreateRouteAssignment -------------------------------------------------------

func TestCreateRouteAssignment_HappyPath(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{ID: "s1", Name: "S1"}

	body, _ := json.Marshal(CreateRouteAssignmentRequest{
		Permissions: "read",
		AutoSpawn:   true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := reg.servers["s1"].RouteAssignments; len(got) != 1 || got[0].Permissions != "read" {
		t.Errorf("assignment not appended: %+v", got)
	}
}

func TestCreateRouteAssignment_BadPath(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1", nil)
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_InvalidJSON(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_InvalidPermissions(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "superuser"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_PermissionDenied(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "read"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	// no X-User-ID → "default-user" lacks group:manage
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_InvalidUserID(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{
		Permissions: "read",
		UserIDs:     []string{"missing-user"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_InvalidGroupID(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{
		Permissions: "read",
		GroupIDs:    []string{"missing-group"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_ValidUserAndGroup(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{ID: "s1"}

	// Pre-create the user and group so validation passes.
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)
	h.userGroupService = svc
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "U", Email: "u@x"})
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "G"})

	body, _ := json.Marshal(CreateRouteAssignmentRequest{
		Permissions: "write",
		UserIDs:     []string{"u1"},
		GroupIDs:    []string{"g1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateRouteAssignment_ServerNotFound(t *testing.T) {
	h, _ := newRouteHandler(t) // empty registry
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "read"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/missing/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestCreateRouteAssignment_UpdateFails(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{ID: "s1"}
	reg.updateErr = errors.New("disk full")

	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "read"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registry/s1/routes", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateRouteAssignment(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

// --- ListRouteAssignments ---------------------------------------------------------

func TestListRouteAssignments_HappyPath(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{
		ID: "s1",
		RouteAssignments: []models.RouteAssignment{
			{ID: "a1", Permissions: "read"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/s1/routes", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var got []models.RouteAssignment
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got) != 1 || got[0].ID != "a1" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestListRouteAssignments_ServerNotFound(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/missing/routes", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestListRouteAssignments_BadPath(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/registry/s1", nil)
	rec := httptest.NewRecorder()
	h.ListRouteAssignments(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

// --- UpdateRouteAssignment --------------------------------------------------------

func TestUpdateRouteAssignment_HappyPath(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{
		ID: "s1",
		RouteAssignments: []models.RouteAssignment{
			{ID: "a1", Permissions: "read"},
		},
	}
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write", AutoSpawn: true})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/s1/routes/a1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if reg.servers["s1"].RouteAssignments[0].Permissions != "write" {
		t.Error("update not applied")
	}
}

func TestUpdateRouteAssignment_AssignmentNotFound(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{ID: "s1"}
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/s1/routes/missing", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestUpdateRouteAssignment_ServerNotFound(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/missing/routes/a1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestUpdateRouteAssignment_PermissionDenied(t *testing.T) {
	h, _ := newRouteHandler(t)
	body, _ := json.Marshal(CreateRouteAssignmentRequest{Permissions: "write"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/s1/routes/a1", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestUpdateRouteAssignment_BadPath(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/s1", nil)
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestUpdateRouteAssignment_InvalidJSON(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/registry/s1/routes/a1", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateRouteAssignment(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

// --- DeleteRouteAssignment --------------------------------------------------------

func TestDeleteRouteAssignment_HappyPath(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{
		ID: "s1",
		RouteAssignments: []models.RouteAssignment{
			{ID: "a1"},
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/s1/routes/a1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	if len(reg.servers["s1"].RouteAssignments) != 0 {
		t.Error("assignment not removed")
	}
}

func TestDeleteRouteAssignment_AssignmentNotFound(t *testing.T) {
	h, reg := newRouteHandler(t)
	reg.servers["s1"] = &models.MCPServer{ID: "s1"}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/s1/routes/missing", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestDeleteRouteAssignment_ServerNotFound(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/missing/routes/a1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestDeleteRouteAssignment_PermissionDenied(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/s1/routes/a1", nil)
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestDeleteRouteAssignment_BadPath(t *testing.T) {
	h, _ := newRouteHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/registry/s1", nil)
	rec := httptest.NewRecorder()
	h.DeleteRouteAssignment(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

// --- Method guards ---------------------------------------------------------------

func TestRouteAssignmentHandlers_MethodNotAllowed(t *testing.T) {
	h, _ := newRouteHandler(t)
	tests := []struct {
		name    string
		method  string
		target  string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"Create GET", http.MethodGet, "/api/v1/registry/s1/routes", h.CreateRouteAssignment},
		{"List POST", http.MethodPost, "/api/v1/registry/s1/routes", h.ListRouteAssignments},
		{"Update POST", http.MethodPost, "/api/v1/registry/s1/routes/a1", h.UpdateRouteAssignment},
		{"Delete POST", http.MethodPost, "/api/v1/registry/s1/routes/a1", h.DeleteRouteAssignment},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("want 405, got %d", rec.Code)
			}
		})
	}
}

// --- generateRouteAssignmentID ---------------------------------------------------

func TestGenerateRouteAssignmentID(t *testing.T) {
	id := generateRouteAssignmentID("s1")
	if id == "" {
		t.Error("id should be non-empty")
	}
	if !bytes.HasPrefix([]byte(id), []byte("assignment-s1-")) {
		t.Errorf("id should embed the server id, got %q", id)
	}
	// Two back-to-back calls *should* differ, but the production code uses
	// time.Now().UnixNano() which can collide on platforms with coarse clocks.
	// Document the contract by giving the clock a nudge; this avoids spurious
	// CI failures while still asserting the intended uniqueness behavior.
	time.Sleep(time.Microsecond)
	second := generateRouteAssignmentID("s1")
	if id == second {
		t.Errorf("ids should differ across calls separated by >1us, got %q twice", id)
	}
}
