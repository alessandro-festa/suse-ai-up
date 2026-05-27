package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"suse-ai-up/pkg/models"
)

// CreateGroupRequest represents a request to create a group
type CreateGroupRequest struct {
	ID          string   `json:"id" example:"weather-team"`
	Name        string   `json:"name" example:"Weather Team"`
	Description string   `json:"description" example:"Team with access to weather APIs"`
	Permissions []string `json:"permissions,omitempty" example:"[\"server:weather-*\"]"`
}

// CreateGroupResponse represents the response for group creation
type CreateGroupResponse struct {
	Group     models.Group `json:"group"`
	CreatedAt time.Time    `json:"createdAt"`
}

// UpdateGroupRequest represents a request to update a group
type UpdateGroupRequest struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// CreateGroup creates a new group
// CreateGroup handles POST /api/v1/groups
// @Summary Create a new group
// @Description Create a new group in the system
// @Tags groups
// @Accept json
// @Produce json
// @Param group body CreateGroupRequest true "Group data"
// @Success 201 {object} models.Group
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups [post]
func (h *UserGroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	// Basic validation
	if req.ID == "" || req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "id and name are required"})
		return
	}

	// Check permissions
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageGroups(r.Context(), userID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage groups"})
		return
	}

	// Create group
	group := models.Group{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	if err := h.userGroupService.CreateGroup(r.Context(), group); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create group: " + err.Error()})
		return
	}

	response := CreateGroupResponse{
		Group:     group,
		CreatedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ListGroups handles GET /api/v1/groups
// @Summary List all groups
// @Description Retrieve a list of all groups in the system
// @Tags groups
// @Produce json
// @Success 200 {array} models.Group
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups [get]
func (h *UserGroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	groups, err := h.userGroupService.ListGroups(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to list groups: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

// GetGroup gets a specific group by ID
// GetGroup handles GET /api/v1/groups/{id}
// @Summary Get group details
// @Description Retrieve details of a specific group
// @Tags groups
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} models.Group
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups/{id} [get]
func (h *UserGroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	groupID := strings.Split(path, "/")[0]

	group, err := h.userGroupService.GetGroup(r.Context(), groupID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Group not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to get group: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(group)
}

// UpdateGroup updates an existing group
// UpdateGroup handles PUT /api/v1/groups/{id}
// @Summary Update a group
// @Description Update an existing group's information
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param group body UpdateGroupRequest true "Updated group data"
// @Success 200 {object} models.Group
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups/{id} [put]
func (h *UserGroupHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	groupID := strings.Split(path, "/")[0]

	var req UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	// Check permissions
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageGroups(r.Context(), userID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage groups"})
		return
	}

	// Get existing group
	group, err := h.userGroupService.GetGroup(r.Context(), groupID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Group not found"})
		return
	}

	// Update fields
	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}
	if req.Permissions != nil {
		group.Permissions = req.Permissions
	}

	if err := h.userGroupService.UpdateGroup(r.Context(), *group); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to update group: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(group)
}

// DeleteGroup deletes a group
// DeleteGroup handles DELETE /api/v1/groups/{id}
// @Summary Delete a group
// @Description Delete a group from the system
// @Tags groups
// @Produce json
// @Param id path string true "Group ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups/{id} [delete]
func (h *UserGroupHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	groupID := strings.Split(path, "/")[0]

	// Check permissions
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageGroups(r.Context(), userID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage groups"})
		return
	}

	if err := h.userGroupService.DeleteGroup(r.Context(), groupID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Group not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to delete group: " + err.Error()})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
