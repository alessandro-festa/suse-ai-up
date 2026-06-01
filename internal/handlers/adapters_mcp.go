package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/models"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
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

	// Get user ID from header (set by UserAuthMiddleware in CR mode)
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user" // For development
	}

	// Get adapter for ACL fields. Uses GetAdapter (with CreatedBy +
	// admin-bypass check) — preserves today's "user can only invoke
	// their own adapters" semantics on this direct path.
	adapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
		return
	}

	// RouteAssignment ACL enforcement (P2.5a). When no assignmentRegistry
	// is wired, behavior is unchanged (legacy allow-all). When wired, the
	// effective ACL set is computed from the in-memory store — zero
	// per-request k8s calls — and unmatched subjects get 403. Adapters
	// with no RouteAssignments stay allow-all (fail-open).
	if h.assignmentRegistry != nil {
		asgs := authsvc.EffectiveAssignments(h.assignmentRegistry, h.namespace, adapter.RouteAssignmentRefs, adapter.MCPServerID)
		required := authsvc.MethodPermission(r.Method)
		var userGroups []string
		if u, err := h.userGroupService.GetUser(r.Context(), userID); err == nil && u != nil {
			userGroups = u.Groups
		}
		if !authsvc.Allowed(userID, userGroups, asgs, required) {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions for this adapter"})
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Failed to read request body: " + err.Error()})
		return
	}

	sc, ct, resp, err := h.ProxyMCPToAdapter(r.Context(), adapterID, userID, body, r.Header)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(sc)
	_, _ = w.Write(resp)
}

// ProxyMCPToAdapter dispatches a JSON-RPC body to the named adapter's
// configured upstream — sidecar URL, remote HTTP URL, or a synthesized
// LocalStdio init response. Used by HandleMCPProtocol (direct
// /api/v1/adapters/{name}/mcp callers) and the VirtualMCPRouteHandler
// (after reverse-resolving a tool name to its origin adapter and
// rewriting params.name).
//
// Does NOT do auth or RouteAssignment ACL — those are caller-owned.
// Adapter lookup goes through AdapterService.GetRaw, bypassing the
// CreatedBy check (vroute callers may not own the source adapter; the
// route's ACL is the authority for them).
//
// Returns (statusCode, contentType, response, err). Transport errors
// against the upstream surface as a non-nil err with statusCode=0
// (caller should respond 500); upstream HTTP error responses surface
// as a non-error return with the upstream's statusCode and body so the
// caller can pass them through.
func (h *AdapterHandler) ProxyMCPToAdapter(ctx context.Context, adapterID, userID string, body []byte, headers http.Header) (int, string, []byte, error) {
	adapter, err := h.adapterService.GetRaw(ctx, adapterID)
	if err != nil {
		return 0, "", nil, fmt.Errorf("adapter not found: %w", err)
	}

	switch {
	case adapter.ConnectionType == models.ConnectionTypeStreamableHttp && adapter.SidecarConfig != nil:
		port := 8000
		if adapter.SidecarConfig.Port != 0 {
			port = adapter.SidecarConfig.Port
		}
		sidecarURL := fmt.Sprintf("http://mcp-sidecar-%s.suse-ai-up-mcp.svc.cluster.local:%d/mcp", adapterID, port)
		return h.dispatchToSidecar(ctx, adapterID, sidecarURL, body, headers)

	case adapter.ConnectionType == models.ConnectionTypeLocalStdio,
		adapter.ConnectionType == models.ConnectionTypeStreamableHttp && adapter.SidecarConfig == nil:
		return synthesizeMCPInit(adapter)

	case adapter.ConnectionType == models.ConnectionTypeRemoteHttp:
		if adapter.RemoteUrl == "" {
			payload, _ := json.Marshal(ErrorResponse{Error: "Remote URL not configured for adapter"})
			return http.StatusBadRequest, "application/json", payload, nil
		}
		return dispatchToRemote(ctx, adapter, body, headers)

	default:
		payload, _ := json.Marshal(ErrorResponse{Error: "MCP protocol not supported for this adapter type"})
		return http.StatusNotImplemented, "application/json", payload, nil
	}
}

// synthesizeMCPInit returns the canned MCP initialize response served
// for LocalStdio adapters and StreamableHttp adapters without a
// SidecarConfig. Matches the pre-refactor behavior of HandleMCPProtocol.
func synthesizeMCPInit(adapter *models.AdapterResource) (int, string, []byte, error) {
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
	out, err := json.Marshal(response)
	if err != nil {
		return 0, "", nil, fmt.Errorf("marshal init response: %w", err)
	}
	return http.StatusOK, "application/json", out, nil
}

// dispatchToRemote forwards the body to a RemoteHttp adapter's remote
// MCP server. Auth header is rewritten when the adapter declares a
// GitHub token in its EnvironmentVariables (preserves the pre-refactor
// behavior of proxyToRemoteMCP).
func dispatchToRemote(ctx context.Context, adapter *models.AdapterResource, body []byte, headers http.Header) (int, string, []byte, error) {
	remoteReq, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.RemoteUrl, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, fmt.Errorf("create remote request: %w", err)
	}

	for key, values := range headers {
		if strings.EqualFold(key, "authorization") {
			if token := adapter.EnvironmentVariables["GITHUB_PERSONAL_ACCESS_TOKEN"]; token != "" {
				remoteReq.Header.Set("Authorization", "Bearer "+token)
			} else if token := adapter.EnvironmentVariables["GITHUB_ACCESS_TOKEN"]; token != "" {
				remoteReq.Header.Set("Authorization", "Bearer "+token)
			}
			continue
		}
		for _, value := range values {
			remoteReq.Header.Add(key, value)
		}
	}
	if remoteReq.Header.Get("Content-Type") == "" {
		remoteReq.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(remoteReq)
	if err != nil {
		payload, _ := json.Marshal(ErrorResponse{Error: "Failed to connect to remote MCP server"})
		return http.StatusBadGateway, "application/json", payload, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", nil, fmt.Errorf("read remote response: %w", err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), respBody, nil
}

// dispatchToSidecar forwards the body to a sidecar MCP server. The
// response is read into memory so any sidecar URLs in JSON payloads
// can be rewritten to point at the proxy's adapter URL (preserves the
// pre-refactor behavior of proxyToSidecar).
func (h *AdapterHandler) dispatchToSidecar(ctx context.Context, adapterID, sidecarURL string, body []byte, headers http.Header) (int, string, []byte, error) {
	sidecarReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, fmt.Errorf("create sidecar request: %w", err)
	}

	for key, values := range headers {
		for _, value := range values {
			sidecarReq.Header.Add(key, value)
		}
	}
	if sidecarReq.Header.Get("Accept") == "" {
		sidecarReq.Header.Set("Accept", "application/json, text/event-stream")
	}
	if sidecarReq.Header.Get("Content-Type") == "" {
		sidecarReq.Header.Set("Content-Type", "application/json")
	}
	sidecarReq.Host = "localhost"

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(sidecarReq)
	if err != nil {
		payload, _ := json.Marshal(ErrorResponse{Error: "UNIQUE_ERROR: Failed to connect to sidecar: " + err.Error()})
		return http.StatusBadGateway, "application/json", payload, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Don't pass through redirects — they would expose internal URLs.
		payload, _ := json.Marshal(ErrorResponse{Error: "Sidecar returned redirect - internal routing issue"})
		return http.StatusBadGateway, "application/json", payload, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", nil, fmt.Errorf("read sidecar response: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		bodyBytes = []byte(h.rewriteSidecarURLs(string(bodyBytes), adapterID))
	}
	return resp.StatusCode, contentType, bodyBytes, nil
}

// rewriteSidecarURLs rewrites any sidecar URLs in the response to proxy URLs
func (h *AdapterHandler) rewriteSidecarURLs(responseBody, adapterID string) string {
	sidecarBaseURL := fmt.Sprintf("http://mcp-sidecar-%s.suse-ai-up-mcp.svc.cluster.local", adapterID)
	proxyBaseURL := fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s", adapterID)
	return strings.ReplaceAll(responseBody, sidecarBaseURL, proxyBaseURL)
}
