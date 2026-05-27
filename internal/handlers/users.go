package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	ID     string   `json:"id" example:"user123"`
	Name   string   `json:"name" example:"John Doe"`
	Email  string   `json:"email" example:"john@example.com"`
	Groups []string `json:"groups,omitempty" example:"[\"mcp-users\"]"`
}

// CreateUserResponse represents the response for user creation
type CreateUserResponse struct {
	User      models.User `json:"user"`
	CreatedAt time.Time   `json:"createdAt"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// CreateUser creates a new user
// CreateUser handles POST /api/v1/users
// @Summary Create a new user
// @Description Create a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "User data"
// @Success 201 {object} CreateUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/users [post]
func (h *UserGroupHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	// Basic validation
	if req.ID == "" || req.Name == "" || req.Email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "id, name, and email are required"})
		return
	}

	// Check permissions
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageUsers(r.Context(), userID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage users"})
		return
	}

	// Create user
	user := models.User{
		ID:     req.ID,
		Name:   req.Name,
		Email:  req.Email,
		Groups: req.Groups,
	}

	if err := h.userGroupService.CreateUser(r.Context(), user); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create user: " + err.Error()})
		return
	}

	response := CreateUserResponse{
		User:      user,
		CreatedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ListUsers handles GET /api/v1/users
// @Summary List all users
// @Description Retrieve a list of all users in the system
// @Tags users
// @Produce json
// @Success 200 {array} models.User
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/users [get]
func (h *UserGroupHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := h.userGroupService.ListUsers(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to list users: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GetUser gets a specific user by ID
// GetUser handles GET /api/v1/users/{id}
// @Summary Get user details
// @Description Retrieve details of a specific user
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} models.User
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/users/{id} [get]
func (h *UserGroupHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID := strings.Split(path, "/")[0]

	user, err := h.userGroupService.GetUser(r.Context(), userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "User not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to get user: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// UpdateUser updates an existing user
// UpdateUser handles PUT /api/v1/users/{id}
// @Summary Update a user
// @Description Update an existing user's information
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body UpdateUserRequest true "Updated user data"
// @Success 200 {object} models.User
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/users/{id} [put]
func (h *UserGroupHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID := strings.Split(path, "/")[0]

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	// Check permissions
	currentUserID := r.Header.Get("X-User-ID")
	if currentUserID == "" {
		currentUserID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageUsers(r.Context(), currentUserID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage users"})
		return
	}

	// Get existing user
	user, err := h.userGroupService.GetUser(r.Context(), userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "User not found"})
		return
	}

	// Update fields
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Groups != nil {
		user.Groups = req.Groups
	}

	if err := h.userGroupService.UpdateUser(r.Context(), *user); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to update user: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// DeleteUser deletes a user
// DeleteUser handles DELETE /api/v1/users/{id}
// @Summary Delete a user
// @Description Delete a user from the system
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/users/{id} [delete]
func (h *UserGroupHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID := strings.Split(path, "/")[0]

	// Check permissions
	currentUserID := r.Header.Get("X-User-ID")
	if currentUserID == "" {
		currentUserID = "default-user"
	}

	canManage, err := h.userGroupService.CanManageUsers(r.Context(), currentUserID)
	if err != nil || !canManage {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Insufficient permissions to manage users"})
		return
	}

	if err := h.userGroupService.DeleteUser(r.Context(), userID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "User not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to delete user: " + err.Error()})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
