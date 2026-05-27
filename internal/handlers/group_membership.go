package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AddUserToGroupRequest represents a request to add a user to a group
type AddUserToGroupRequest struct {
	UserID string `json:"userId" example:"user123"`
}

// AddUserToGroup adds a user to a group
// AddUserToGroup handles POST /api/v1/groups/{id}/members
// @Summary Add user to group
// @Description Add a user to a specific group
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param request body AddUserToGroupRequest true "User to add"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups/{id}/members [post]
func (h *UserGroupHandler) AddUserToGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "members" {
		http.NotFound(w, r)
		return
	}
	groupID := parts[0]

	var req AddUserToGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.UserID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "userId is required"})
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

	if err := h.userGroupService.AddUserToGroup(r.Context(), groupID, req.UserID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to add user to group: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "user_added",
		"message": fmt.Sprintf("User %s added to group %s", req.UserID, groupID),
	})
}

// RemoveUserFromGroup removes a user from a group
// RemoveUserFromGroup handles DELETE /api/v1/groups/{id}/members/{userId}
// @Summary Remove user from group
// @Description Remove a user from a specific group
// @Tags groups
// @Produce json
// @Param id path string true "Group ID"
// @Param userId path string true "User ID to remove"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/groups/{id}/members/{userId} [delete]
func (h *UserGroupHandler) RemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract group ID and user ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/groups/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[1] != "members" {
		http.NotFound(w, r)
		return
	}
	groupID := parts[0]
	userID := parts[2]

	// Check permissions
	currentUserID := r.Header.Get("X-User-ID")
	if currentUserID == "" {
		currentUserID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageGroups(r.Context(), currentUserID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage groups"})
		return
	}

	if err := h.userGroupService.RemoveUserFromGroup(r.Context(), groupID, userID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to remove user from group: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "user_removed",
		"message": fmt.Sprintf("User %s removed from group %s", userID, groupID),
	})
}
