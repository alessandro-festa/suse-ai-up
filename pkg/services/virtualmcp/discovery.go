// Package virtualmcp owns everything related to virtual-MCP services:
// today's remote-discovery flow (this file) and Phase 2's route composition
// from registered adapters (composition.go).
//
// Phase 1 mirrors the behavior previously inlined in
// pkg/plugins/manager.go: poll a remote VirtualMCP service's /api/v1/mcps
// endpoint and convert each implementation into a models.MCPServer that the
// registry can ingest. The caller (the plugin manager) owns registry
// insertion so this package stays free of registry-store coupling.
package virtualmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"suse-ai-up/pkg/models"
)

// SourceLabel is the canonical "source" tag stamped onto every MCPServer
// produced by virtual-MCP discovery. Handlers downstream branch on this
// value to decide e.g. that the adapter should be wired up as remote-HTTP.
const SourceLabel = "virtualmcp"

// Discoverer queries a remote VirtualMCP service for its MCP implementations
// and converts the response into models.MCPServer entries.
type Discoverer struct {
	httpClient *http.Client
}

// NewDiscoverer builds a Discoverer. If httpClient is nil, a default client
// with a 30 s timeout (matching the previous inline behavior) is used.
func NewDiscoverer(httpClient *http.Client) *Discoverer {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Discoverer{httpClient: httpClient}
}

// HealthStatus describes a VirtualMCP service's reachability and discovery
// readiness without leaking the plugin manager's ServiceHealth shape into
// this package. The caller wraps it into whatever its own model expects.
type HealthStatus struct {
	Status  string // "healthy", "unhealthy", "degraded"
	Message string
}

// Discover queries serviceURL/api/v1/mcps and returns the converted MCPServer
// entries. The caller owns registry insertion.
func (d *Discoverer) Discover(ctx context.Context, serviceID, serviceURL string) ([]*models.MCPServer, error) {
	log.Printf("Discovering MCP implementations from VirtualMCP service: %s", serviceID)

	discoveryURL := fmt.Sprintf("%s/api/v1/mcps", serviceURL)
	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call discovery endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read discovery response: %w", err)
	}

	var discoveryResponse struct {
		Implementations []map[string]interface{} `json:"implementations"`
		Count           int                      `json:"count"`
		Service         string                   `json:"service"`
	}
	if err := json.Unmarshal(body, &discoveryResponse); err != nil {
		return nil, fmt.Errorf("parse discovery response: %w", err)
	}

	log.Printf("Discovered %d MCP implementations from %s", len(discoveryResponse.Implementations), serviceID)

	servers := make([]*models.MCPServer, 0, len(discoveryResponse.Implementations))
	for _, impl := range discoveryResponse.Implementations {
		if srv := convertImplementation(impl, serviceID, serviceURL); srv != nil {
			servers = append(servers, srv)
		}
	}
	return servers, nil
}

// CheckHealth probes serviceURL/health and serviceURL/api/v1/mcps. A failed
// /health is unhealthy; reachable /health with a broken /api/v1/mcps is
// degraded.
func (d *Discoverer) CheckHealth(ctx context.Context, serviceURL string) HealthStatus {
	healthURL := fmt.Sprintf("%s/health", serviceURL)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Failed to create health check request: %v", err),
		}
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Health check failed: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Health check returned status %d", resp.StatusCode),
		}
	}

	mcpURL := fmt.Sprintf("%s/api/v1/mcps", serviceURL)
	req2, err := http.NewRequestWithContext(ctx, "GET", mcpURL, nil)
	if err != nil {
		return HealthStatus{
			Status:  "degraded",
			Message: "Basic health OK but MCP discovery check failed",
		}
	}

	resp2, err := d.httpClient.Do(req2)
	if err != nil {
		return HealthStatus{
			Status:  "degraded",
			Message: fmt.Sprintf("Basic health OK but MCP discovery failed: %v", err),
		}
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return HealthStatus{
			Status:  "degraded",
			Message: fmt.Sprintf("Basic health OK but MCP discovery returned status %d", resp2.StatusCode),
		}
	}

	var discoveryResponse struct {
		Count int `json:"count"`
	}
	body, err := io.ReadAll(resp2.Body)
	if err == nil {
		json.Unmarshal(body, &discoveryResponse)
	}

	return HealthStatus{
		Status:  "healthy",
		Message: fmt.Sprintf("VirtualMCP service healthy with %d MCP implementations", discoveryResponse.Count),
	}
}

// convertImplementation converts one entry from a /api/v1/mcps response into
// an MCPServer. Returns nil if the entry lacks a required field (id).
func convertImplementation(impl map[string]interface{}, serviceID, serviceURL string) *models.MCPServer {
	server := &models.MCPServer{
		ValidationStatus: "new",
		DiscoveredAt:     time.Now(),
		Meta: map[string]interface{}{
			"source":         SourceLabel,
			"service_id":     serviceID,
			"service_url":    serviceURL,
			"discovery_time": time.Now().Format(time.RFC3339),
		},
	}

	if id, ok := impl["id"].(string); ok {
		server.ID = fmt.Sprintf("%s-%s-%s", SourceLabel, serviceID, id)
	} else {
		return nil
	}

	if name, ok := impl["name"].(string); ok {
		server.Name = name
	}
	if description, ok := impl["description"].(string); ok {
		server.Description = description
	}

	server.Version = "1.0.0"
	if version, ok := impl["version"].(string); ok {
		server.Version = version
	}

	server.Packages = []models.Package{
		{
			RegistryType: SourceLabel,
			Identifier:   server.ID,
			Transport: models.Transport{
				Type: "http",
			},
		},
	}

	if tools, ok := impl["tools"].([]interface{}); ok {
		server.Tools = make([]models.MCPTool, 0, len(tools))
		for _, toolData := range tools {
			toolMap, ok := toolData.(map[string]interface{})
			if !ok {
				continue
			}
			tool := models.MCPTool{}
			if name, ok := toolMap["name"].(string); ok {
				tool.Name = name
			}
			if description, ok := toolMap["description"].(string); ok {
				tool.Description = description
			}
			if inputSchema, ok := toolMap["input_schema"].(map[string]interface{}); ok {
				tool.InputSchema = inputSchema
			}
			if sourceType, ok := toolMap["source_type"].(string); ok {
				tool.SourceType = sourceType
			}
			if config, ok := toolMap["config"].(map[string]interface{}); ok {
				tool.Config = config
			}
			server.Tools = append(server.Tools, tool)
		}
	}

	return server
}
