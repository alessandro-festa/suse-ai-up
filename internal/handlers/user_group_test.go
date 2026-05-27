package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
)

// newTestUserGroupHandler wires the real UserGroupService against in-memory stores.
// Using "dev-admin" as the X-User-ID short-circuits permission checks
// (see pkg/services/user_group.go:CanManageUsers / CanManageGroups).
func newTestUserGroupHandler(t *testing.T) (*UserGroupHandler, *services.UserGroupService) {
	t.Helper()
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	svc := services.NewUserGroupService(userStore, groupStore)
	return NewUserGroupHandler(svc), svc
}

func doRequest(method, target string, body interface{}, header map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reader)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return httptest.NewRecorder()
}

// --- HandleUsers / HandleGroups dispatcher --------------------------------------------

func TestHandleUsers_DispatchesByMethod(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)

	// GET → ListUsers (200 + JSON array)
	rec := doRequest(http.MethodGet, "/api/v1/users", nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	h.HandleUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET want 200, got %d", rec.Code)
	}

	// Unsupported method → 405
	rec = doRequest(http.MethodPatch, "/api/v1/users", nil, nil)
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users", nil)
	h.HandleUsers(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH want 405, got %d", rec.Code)
	}
}

func TestHandleGroups_DispatchesByMethod(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	rec := httptest.NewRecorder()
	h.HandleGroups(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET want 200, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/groups", nil)
	rec = httptest.NewRecorder()
	h.HandleGroups(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH want 405, got %d", rec.Code)
	}
}

// --- Users CRUD -----------------------------------------------------------------

func TestCreateUser_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	body, _ := json.Marshal(CreateUserRequest{ID: "u1", Name: "Alice", Email: "a@x.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateUser(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	got, err := svc.GetUser(context.Background(), "u1")
	if err != nil || got.Email != "a@x.com" {
		t.Errorf("user not persisted: %v / %+v", err, got)
	}
}

func TestCreateUser_ValidationFailures(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"invalid json", `not json`, http.StatusBadRequest},
		{"missing fields", `{"id":"u1"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-User-ID", "dev-admin")
			rec := httptest.NewRecorder()
			h.CreateUser(rec, req)
			if rec.Code != tc.code {
				t.Errorf("want %d, got %d", tc.code, rec.Code)
			}
		})
	}
}

func TestCreateUser_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(CreateUserRequest{ID: "u1", Name: "A", Email: "a@x.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	// no X-User-ID → defaults to "default-user", which lacks user:manage
	rec := httptest.NewRecorder()
	h.CreateUser(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestCreateUser_WrongMethod(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	h.CreateUser(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", rec.Code)
	}
}

func TestListUsers_ReturnsAll(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateUser(context.Background(), models.User{ID: "a", Name: "A", Email: "a@x"})
	_ = svc.CreateUser(context.Background(), models.User{ID: "b", Name: "B", Email: "b@x"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var users []models.User
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users) != 2 {
		t.Errorf("want 2 users, got %d", len(users))
	}
}

func TestGetUser_FoundAndNotFound(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "U", Email: "u@x"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/u1", nil)
	rec := httptest.NewRecorder()
	h.GetUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("found want 200, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/missing", nil)
	rec = httptest.NewRecorder()
	h.GetUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing want 404, got %d", rec.Code)
	}
}

func TestUpdateUser_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "Old", Email: "old@x"})

	body, _ := json.Marshal(UpdateUserRequest{Name: "New", Email: "new@x"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/u1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := svc.GetUser(context.Background(), "u1")
	if got.Name != "New" || got.Email != "new@x" {
		t.Errorf("update not applied: %+v", got)
	}
}

func TestUpdateUser_NotFound(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(UpdateUserRequest{Name: "x"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/missing", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestUpdateUser_InvalidJSON(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/u1", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestUpdateUser_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(UpdateUserRequest{Name: "x"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/u1", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.UpdateUser(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestDeleteUser_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "U", Email: "u@x"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/u1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteUser(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	if _, err := svc.GetUser(context.Background(), "u1"); err == nil {
		t.Error("user should be deleted")
	}
}

func TestDeleteUser_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/u1", nil)
	rec := httptest.NewRecorder()
	h.DeleteUser(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// --- Groups CRUD ----------------------------------------------------------------

func TestCreateGroup_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	body, _ := json.Marshal(CreateGroupRequest{ID: "g1", Name: "Team", Description: "d"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.CreateGroup(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := svc.GetGroup(context.Background(), "g1")
	if got.Name != "Team" {
		t.Errorf("group not persisted: %+v", got)
	}
}

func TestCreateGroup_ValidationFailures(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"invalid json", `not json`, http.StatusBadRequest},
		{"missing fields", `{"id":"g1"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-User-ID", "dev-admin")
			rec := httptest.NewRecorder()
			h.CreateGroup(rec, req)
			if rec.Code != tc.code {
				t.Errorf("want %d, got %d", tc.code, rec.Code)
			}
		})
	}
}

func TestCreateGroup_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(CreateGroupRequest{ID: "g1", Name: "G"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreateGroup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestListGroups_ReturnsAll(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "A"})
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g2", Name: "B"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	rec := httptest.NewRecorder()
	h.ListGroups(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var groups []models.Group
	_ = json.Unmarshal(rec.Body.Bytes(), &groups)
	if len(groups) != 2 {
		t.Errorf("want 2 groups, got %d", len(groups))
	}
}

func TestGetGroup_FoundAndNotFound(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "G"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/g1", nil)
	rec := httptest.NewRecorder()
	h.GetGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("found want 200, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/groups/missing", nil)
	rec = httptest.NewRecorder()
	h.GetGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing want 404, got %d", rec.Code)
	}
}

func TestUpdateGroup_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "Old"})

	body, _ := json.Marshal(UpdateGroupRequest{Name: "New", Description: "d"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/g1", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := svc.GetGroup(context.Background(), "g1")
	if got.Name != "New" {
		t.Errorf("update not applied: %+v", got)
	}
}

func TestUpdateGroup_NotFound(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(UpdateGroupRequest{Name: "x"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/missing", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestUpdateGroup_InvalidJSON(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/g1", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.UpdateGroup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestUpdateGroup_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(UpdateGroupRequest{Name: "x"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/g1", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.UpdateGroup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestDeleteGroup_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "G"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/g1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.DeleteGroup(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	if _, err := svc.GetGroup(context.Background(), "g1"); err == nil {
		t.Error("group should be deleted")
	}
}

func TestDeleteGroup_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/g1", nil)
	rec := httptest.NewRecorder()
	h.DeleteGroup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// --- Group membership -----------------------------------------------------------

func TestAddUserToGroup_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "G"})
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "U", Email: "u@x"})

	body, _ := json.Marshal(AddUserToGroupRequest{UserID: "u1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/g1/members", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.AddUserToGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// AddUserToGroup updates the group's Members slice, not the user's Groups slice
	// (membership is tracked on the group side).
	members, _ := svc.GetGroupMembers(context.Background(), "g1")
	if len(members) != 1 || members[0].ID != "u1" {
		t.Errorf("user not in group members: %+v", members)
	}
}

func TestAddUserToGroup_BadPath(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/g1", nil)
	rec := httptest.NewRecorder()
	h.AddUserToGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestAddUserToGroup_MissingUserID(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(AddUserToGroupRequest{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/g1/members", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.AddUserToGroup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestAddUserToGroup_InvalidJSON(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/g1/members", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.AddUserToGroup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestAddUserToGroup_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	body, _ := json.Marshal(AddUserToGroupRequest{UserID: "u1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/g1/members", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.AddUserToGroup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestRemoveUserFromGroup_HappyPath(t *testing.T) {
	h, svc := newTestUserGroupHandler(t)
	_ = svc.CreateGroup(context.Background(), models.Group{ID: "g1", Name: "G"})
	_ = svc.CreateUser(context.Background(), models.User{ID: "u1", Name: "U", Email: "u@x"})
	_ = svc.AddUserToGroup(context.Background(), "g1", "u1")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/g1/members/u1", nil)
	req.Header.Set("X-User-ID", "dev-admin")
	rec := httptest.NewRecorder()
	h.RemoveUserFromGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	members, _ := svc.GetGroupMembers(context.Background(), "g1")
	if len(members) != 0 {
		t.Errorf("user still in group: %+v", members)
	}
}

func TestRemoveUserFromGroup_BadPath(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/g1/members", nil)
	rec := httptest.NewRecorder()
	h.RemoveUserFromGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestRemoveUserFromGroup_PermissionDenied(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/g1/members/u1", nil)
	rec := httptest.NewRecorder()
	h.RemoveUserFromGroup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// --- Method guards ---------------------------------------------------------------

func TestUserGroupHandlers_MethodNotAllowed(t *testing.T) {
	h, _ := newTestUserGroupHandler(t)
	tests := []struct {
		name    string
		method  string
		target  string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"ListUsers POST", http.MethodPost, "/api/v1/users", h.ListUsers},
		{"GetUser POST", http.MethodPost, "/api/v1/users/u1", h.GetUser},
		{"UpdateUser POST", http.MethodPost, "/api/v1/users/u1", h.UpdateUser},
		{"DeleteUser POST", http.MethodPost, "/api/v1/users/u1", h.DeleteUser},
		{"ListGroups POST", http.MethodPost, "/api/v1/groups", h.ListGroups},
		{"GetGroup POST", http.MethodPost, "/api/v1/groups/g1", h.GetGroup},
		{"UpdateGroup POST", http.MethodPost, "/api/v1/groups/g1", h.UpdateGroup},
		{"DeleteGroup POST", http.MethodPost, "/api/v1/groups/g1", h.DeleteGroup},
		{"AddUserToGroup GET", http.MethodGet, "/api/v1/groups/g1/members", h.AddUserToGroup},
		{"RemoveUserFromGroup GET", http.MethodGet, "/api/v1/groups/g1/members/u1", h.RemoveUserFromGroup},
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
