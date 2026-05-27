package handlers

import (
	"net/http"

	"github.com/SUSE/suse-ai-up/pkg/services"
)

// UserGroupHandler handles user and group management requests
type UserGroupHandler struct {
	userGroupService *services.UserGroupService
}

// NewUserGroupHandler creates a new user/group handler
func NewUserGroupHandler(userGroupService *services.UserGroupService) *UserGroupHandler {
	return &UserGroupHandler{
		userGroupService: userGroupService,
	}
}

// HandleUsers handles both listing and creating users
func (h *UserGroupHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListUsers(w, r)
	case http.MethodPost:
		h.CreateUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleGroups handles both listing and creating groups
func (h *UserGroupHandler) HandleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListGroups(w, r)
	case http.MethodPost:
		h.CreateGroup(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
