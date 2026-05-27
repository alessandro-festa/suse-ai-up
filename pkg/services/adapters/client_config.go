package services

import (
	"fmt"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

// BuildCreateClientConfig returns the per-MCP-client (gemini, vscode) MCP
// configuration shape returned by POST /api/v1/adapters. The shape depends on
// the adapter's connection type:
//   - RemoteHttp: direct connection to the upstream URL.
//   - StreamableHttp: routed through the local proxy endpoint.
//   - Anything else: a stdio sentinel.
//
// Today the proxy URL is hardcoded to http://localhost:8911 and the bearer
// token to a placeholder string — both move with this code unchanged and are
// flagged as out-of-scope cleanup.
func BuildCreateClientConfig(adapter *models.AdapterResource) map[string]interface{} {
	switch adapter.ConnectionType {
	case models.ConnectionTypeRemoteHttp:
		return map[string]interface{}{
			"gemini": map[string]interface{}{
				"mcpServers": map[string]interface{}{
					adapter.ID: map[string]interface{}{
						"url": adapter.RemoteUrl,
						"headers": map[string]string{
							"Authorization": "Bearer adapter-session-token",
						},
					},
				},
			},
			"vscode": map[string]interface{}{
				"inputs": []interface{}{},
				"servers": map[string]interface{}{
					adapter.ID: map[string]interface{}{
						"type": "http",
						"url":  adapter.RemoteUrl,
						"headers": map[string]string{
							"Authorization": "Bearer adapter-session-token",
						},
					},
				},
			},
		}
	case models.ConnectionTypeStreamableHttp:
		return map[string]interface{}{
			"gemini": map[string]interface{}{
				"mcpServers": map[string]interface{}{
					adapter.ID: map[string]interface{}{
						"httpUrl": fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s/mcp", adapter.ID),
						"headers": map[string]string{
							"Authorization": "Bearer adapter-session-token",
						},
					},
				},
			},
			"vscode": map[string]interface{}{
				"servers": map[string]interface{}{
					adapter.ID: map[string]interface{}{
						"url": fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s/mcp", adapter.ID),
						"headers": map[string]string{
							"Authorization": "Bearer adapter-session-token",
						},
						"type": "http",
					},
				},
				"inputs": []interface{}{},
			},
		}
	default:
		return map[string]interface{}{"stdio": "format"}
	}
}

// BuildListClientConfig returns the per-MCP-client configuration shape
// included in each entry of GET /api/v1/adapters. Today it's a single shape
// that always uses the adapter's URL (set by the service on creation).
func BuildListClientConfig(adapter *models.AdapterResource) map[string]interface{} {
	return map[string]interface{}{
		"gemini": map[string]interface{}{
			"mcpServers": map[string]interface{}{
				adapter.ID: map[string]interface{}{
					"httpUrl": adapter.URL,
					"headers": map[string]string{
						"Authorization": "Bearer adapter-session-token",
					},
				},
			},
		},
		"vscode": map[string]interface{}{
			"servers": map[string]interface{}{
				adapter.ID: map[string]interface{}{
					"url": adapter.URL,
					"headers": map[string]string{
						"Authorization": "Bearer adapter-session-token",
					},
					"type": "http",
				},
			},
			"inputs": []interface{}{},
		},
	}
}
