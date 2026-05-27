package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/logging"
	"github.com/SUSE/suse-ai-up/pkg/models"
	adaptersvc "github.com/SUSE/suse-ai-up/pkg/services/adapters"
)

// CreateAdapter creates a new adapter from a registry server
func (h *AdapterHandler) CreateAdapter(w http.ResponseWriter, r *http.Request) {
	logging.AdapterLogger.Info("CreateAdapter handler invoked")

	var req CreateAdapterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logging.AdapterLogger.Error("Failed to decode JSON: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	logging.AdapterLogger.Info("Decoded request: mcpServerId=%s, name=%s", req.MCPServerID, req.Name)

	if req.MCPServerID == "" || req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "mcpServerId and name are required"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if req.MCPServerID == "suse-trento" {
		if trentoConfig, exists := req.EnvironmentVariables["TRENTO_CONFIG"]; exists && trentoConfig != "" {
			trentoURL, token, err := adaptersvc.ParseTrentoConfig(trentoConfig)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid TRENTO_CONFIG format: " + err.Error()})
				return
			}

			req.EnvironmentVariables["TRENTO_URL"] = trentoURL
			delete(req.EnvironmentVariables, "TRENTO_CONFIG")

			if req.Authentication == nil {
				req.Authentication = &models.AdapterAuthConfig{}
			}
			req.Authentication.Type = "bearer"
			req.Authentication.BearerToken = &models.BearerTokenConfig{
				Token:   token,
				Dynamic: false,
			}
		}
	}

	adapter, err := h.adapterService.CreateAdapter(
		r.Context(),
		userID,
		req.MCPServerID,
		req.Name,
		req.EnvironmentVariables,
		req.Authentication,
	)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create adapter: " + err.Error()})
		return
	}

	response := CreateAdapterResponse{
		ID:              adapter.ID,
		MCPServerID:     req.MCPServerID,
		MCPClientConfig: adaptersvc.BuildCreateClientConfig(adapter),
		Capabilities:    adapter.MCPFunctionality,
		Status:          "ready",
		CreatedAt:       adapter.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ListAdapters lists all adapters for the current user
func (h *AdapterHandler) ListAdapters(w http.ResponseWriter, r *http.Request) {
	logging.AdapterLogger.Info("ListAdapters handler invoked")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	adapters, err := h.adapterService.ListAdapters(r.Context(), userID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to list adapters: " + err.Error()})
		return
	}

	listAdapters := make([]map[string]interface{}, len(adapters))
	for i := range adapters {
		adapter := &adapters[i]
		listAdapters[i] = map[string]interface{}{
			"id":              adapter.ID,
			"name":            adapter.Name,
			"description":     adapter.Description,
			"url":             adapter.URL,
			"mcpClientConfig": adaptersvc.BuildListClientConfig(adapter),
			"capabilities":    adapter.MCPFunctionality,
			"status":          adapter.Status,
			"createdAt":       adapter.CreatedAt,
			"lastUpdatedAt":   adapter.LastUpdatedAt,
			"createdBy":       adapter.CreatedBy,
			"connectionType":  adapter.ConnectionType,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listAdapters)
}

// GetAdapter gets a specific adapter by ID
// @Summary Get adapter details
// @Description Retrieve details of a specific adapter
// @Tags adapters
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} models.AdapterResource "Adapter details"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name} [get]
func (h *AdapterHandler) GetAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	adapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to get adapter: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adapter)
}

// UpdateAdapter updates an existing adapter
// @Summary Update adapter
// @Description Update an existing adapter's configuration
// @Tags adapters
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter name"
// @Param adapter body models.AdapterData true "Updated adapter data"
// @Success 200 {object} models.AdapterResource
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/adapters/{name} [put]
func (h *AdapterHandler) UpdateAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	currentAdapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to get adapter: " + err.Error()})
		}
		return
	}

	var updateAdapter models.AdapterResource
	if err := json.NewDecoder(r.Body).Decode(&updateAdapter); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	updateAdapter.ID = currentAdapter.ID
	updateAdapter.CreatedBy = currentAdapter.CreatedBy
	updateAdapter.CreatedAt = currentAdapter.CreatedAt
	updateAdapter.LastUpdatedAt = time.Now().UTC()

	if err := h.adapterService.UpdateAdapter(r.Context(), userID, updateAdapter); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to update adapter: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updateAdapter)
}

// CheckAdapterHealth checks and updates the health status of an adapter
// @Summary Check adapter health
// @Description Check the health of an adapter's sidecar and update its status
// @Tags adapters
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter name"
// @Success 200 {object} map[string]string
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/adapters/{name}/health [post]
func (h *AdapterHandler) CheckAdapterHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	pathParts := strings.Split(path, "/")
	adapterID := pathParts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if err := h.adapterService.CheckAdapterHealth(r.Context(), userID, adapterID, h.userGroupService); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to check adapter health: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Adapter health check completed",
		"adapterId": adapterID,
	})
}

// DeleteAdapter deletes an adapter and its associated sidecar resources
// @Summary Delete adapter
// @Description Delete an adapter and clean up its associated resources
// @Tags adapters
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name} [delete]
func (h *AdapterHandler) DeleteAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if err := h.adapterService.DeleteAdapter(r.Context(), userID, adapterID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to delete adapter: " + err.Error()})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SyncAdapterCapabilities syncs capabilities for an adapter
// @Summary Sync adapter capabilities
// @Description Synchronize and refresh the capabilities of an adapter
// @Tags adapters
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]string "Sync result"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/sync [post]
func (h *AdapterHandler) SyncAdapterCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "sync" {
		http.NotFound(w, r)
		return
	}
	adapterID := parts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if err := h.adapterService.SyncAdapterCapabilities(r.Context(), userID, adapterID, h.userGroupService); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to sync capabilities: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "capabilities_synced",
		"message": "Adapter capabilities have been synchronized",
	})
}
