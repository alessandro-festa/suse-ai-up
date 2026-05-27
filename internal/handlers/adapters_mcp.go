package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

// HandleMCPProtocol proxies MCP protocol requests to the sidecar
// @Summary Proxy MCP protocol requests
// @Description Proxy MCP protocol requests (tools, resources, prompts) to the adapter
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/mcp [post]
func (h *AdapterHandler) HandleMCPProtocol(w http.ResponseWriter, r *http.Request) {
	// Extract adapter ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "mcp" {
		http.NotFound(w, r)
		return
	}

	adapterID := parts[0]

	// Get user ID from header (would be set by auth middleware)
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user" // For development
	}

	// Get adapter information
	adapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		return
	}

	// For sidecar adapters (StreamableHttp with sidecar config), proxy to the sidecar
	if adapter.ConnectionType == models.ConnectionTypeStreamableHttp && adapter.SidecarConfig != nil {
		// Construct sidecar URL dynamically using the port from sidecar config
		// Sidecar runs in suse-ai-up-mcp namespace with name mcp-sidecar-{adapterID}
		port := 8000 // default
		if adapter.SidecarConfig != nil {
			port = adapter.SidecarConfig.Port
		}
		// For HTTP transport MCP servers, use internal DNS
		sidecarURL := fmt.Sprintf("http://mcp-sidecar-%s.suse-ai-up-mcp.svc.cluster.local:%d/mcp", adapterID, port)
		h.proxyToSidecar(w, r, sidecarURL)
		return
	}

	// For LocalStdio adapters OR StreamableHttp adapters without sidecar config, return a proper MCP response
	fmt.Printf("DEBUG: Adapter %s - ConnectionType: %s, SidecarConfig: %v\n", adapterID, adapter.ConnectionType, adapter.SidecarConfig)
	if adapter.ConnectionType == models.ConnectionTypeLocalStdio ||
		(adapter.ConnectionType == models.ConnectionTypeStreamableHttp && adapter.SidecarConfig == nil) {
		fmt.Printf("DEBUG: Returning MCP response for LocalStdio adapter %s\n", adapterID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"serverInfo": map[string]interface{}{
					"name":    adapter.Name,
					"version": "1.0.0",
				},
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{
						"listChanged": true,
					},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// For RemoteHttp adapters, proxy to the remote MCP server
	if adapter.ConnectionType == models.ConnectionTypeRemoteHttp {
		if adapter.RemoteUrl == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Remote URL not configured for adapter"})
			return
		}
		h.proxyToRemoteMCP(w, r, adapter.RemoteUrl)
		return
	}

	// For other connection types, return not implemented
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(ErrorResponse{Error: "MCP protocol not supported for this adapter type"})
}

// proxyToRemoteMCP proxies requests to a remote MCP server
func (h *AdapterHandler) proxyToRemoteMCP(w http.ResponseWriter, r *http.Request, remoteURL string) {
	fmt.Printf("DEBUG: Proxying MCP request to remote server: %s\n", remoteURL)

	// Extract adapter ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid adapter path"})
		return
	}
	adapterID := parts[0]

	// Get user ID from header
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user" // For development
	}

	// Get adapter information to access environment variables
	adapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		return
	}

	// Create a new request to the remote MCP server
	remoteReq, err := http.NewRequestWithContext(r.Context(), r.Method, remoteURL, r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create remote request"})
		return
	}

	// Copy headers from the original request, but replace authorization
	for key, values := range r.Header {
		if strings.ToLower(key) == "authorization" {
			// For GitHub, use the personal access token from environment variables
			if token := adapter.EnvironmentVariables["GITHUB_PERSONAL_ACCESS_TOKEN"]; token != "" {
				remoteReq.Header.Set("Authorization", "Bearer "+token)
			} else if token := adapter.EnvironmentVariables["GITHUB_ACCESS_TOKEN"]; token != "" {
				remoteReq.Header.Set("Authorization", "Bearer "+token)
			}
			// Skip the original authorization header
		} else {
			for _, value := range values {
				remoteReq.Header.Add(key, value)
			}
		}
	}

	// Ensure we have the proper content type for MCP
	if remoteReq.Header.Get("Content-Type") == "" {
		remoteReq.Header.Set("Content-Type", "application/json")
	}

	// Make the request to the remote MCP server
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(remoteReq)
	if err != nil {
		fmt.Printf("DEBUG: Failed to connect to remote MCP server %s: %v\n", remoteURL, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to connect to remote MCP server"})
		return
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: Remote MCP server responded with status: %d\n", resp.StatusCode)

	// Copy the response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	io.Copy(w, resp.Body)
}

// proxyToSidecar proxies requests to the sidecar container
func (h *AdapterHandler) proxyToSidecar(w http.ResponseWriter, r *http.Request, sidecarURL string) {

	fmt.Printf("DEBUG: Request headers: %+v\n", r.Header)

	// Extract adapter ID from the request path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/"), "/")
	adapterID := pathParts[0]

	// Create a new request to the sidecar
	sidecarReq, err := http.NewRequestWithContext(r.Context(), r.Method, sidecarURL, r.Body)
	if err != nil {
		fmt.Printf("DEBUG: Failed to create sidecar request: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create sidecar request"})
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			sidecarReq.Header.Add(key, value)
		}
	}

	// Ensure Accept header includes required types for MCP HTTP transport
	if sidecarReq.Header.Get("Accept") == "" {
		sidecarReq.Header.Set("Accept", "application/json, text/event-stream")
	}

	// Set Host header to localhost for MCP servers that may check host
	sidecarReq.Host = "localhost"

	// Set Content-Type if not already set
	if sidecarReq.Header.Get("Content-Type") == "" {
		sidecarReq.Header.Set("Content-Type", "application/json")
	}

	// Make the request to the sidecar
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Don't follow redirects to avoid exposing internal URLs
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(sidecarReq)
	if err != nil {
		fmt.Printf("DEBUG: Failed to connect to sidecar: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "UNIQUE_ERROR: Failed to connect to sidecar: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	fmt.Printf("DEBUG: Sidecar response status: %d, location: %s\n", resp.StatusCode, resp.Header.Get("Location"))

	// If it's a redirect, don't pass it through to avoid exposing internal URLs
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		fmt.Printf("DEBUG: Blocking redirect response to avoid exposing internal URLs\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Sidecar returned redirect - internal routing issue"})
		return
	}

	// Copy response headers (but filter out location headers for redirects)
	for key, values := range resp.Header {
		if strings.ToLower(key) != "location" { // Don't pass through redirect locations
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Read and potentially rewrite the response body
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// For JSON responses, rewrite any sidecar URLs to proxy URLs
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("DEBUG: Failed to read response body: %v\n", err)
			return
		}

		// Rewrite URLs in the response
		rewrittenBody := h.rewriteSidecarURLs(string(bodyBytes), adapterID)
		w.Write([]byte(rewrittenBody))
	} else {
		// For non-JSON responses, copy directly
		io.Copy(w, resp.Body)
	}
}

// rewriteSidecarURLs rewrites any sidecar URLs in the response to proxy URLs
func (h *AdapterHandler) rewriteSidecarURLs(responseBody, adapterID string) string {
	// Construct the sidecar base URL pattern
	sidecarBaseURL := fmt.Sprintf("http://mcp-sidecar-%s.suse-ai-up-mcp.svc.cluster.local", adapterID)

	// Replace sidecar URLs with proxy URLs
	proxyBaseURL := fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s", adapterID)

	// Replace any occurrences of sidecar URLs with proxy URLs
	rewritten := strings.ReplaceAll(responseBody, sidecarBaseURL, proxyBaseURL)

	if rewritten != responseBody {
		fmt.Printf("DEBUG: Rewrote sidecar URLs in response\n")
	}

	return rewritten
}
