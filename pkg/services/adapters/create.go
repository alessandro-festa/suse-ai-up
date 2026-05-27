package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/logging"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// CreateAdapter creates a new adapter from a registry server
func (as *AdapterService) CreateAdapter(ctx context.Context, userID, mcpServerID, name string, envVars map[string]string, auth *models.AdapterAuthConfig) (*models.AdapterResource, error) {
	logging.AdapterLogger.Info("ADAPTER_SERVICE: CreateAdapter started for server ID %s (user: %s)", mcpServerID, userID)

	// Get the MCP server from registry - first try by ID, then by name
	server, err := as.registryStore.GetMCPServer(mcpServerID)
	if err != nil {
		// If not found by ID, try to find by name
		servers := as.registryStore.ListMCPServers()
		for _, s := range servers {
			if s.Name == mcpServerID {
				server = s
				break
			}
		}
	}
	if server == nil {
		logging.AdapterLogger.Error("MCP server not found: %s", mcpServerID)
		return nil, fmt.Errorf("MCP server not found: %s", mcpServerID)
	}

	logging.AdapterLogger.Info("Retrieved server %s with %d packages", server.Name, len(server.Packages))
	if len(server.Packages) > 0 {
		logging.AdapterLogger.Info("Server transport: %s", server.Packages[0].Transport.Type)
	}

	// Validate required environment variables
	if server.Meta != nil {
		if userAuthRequired, ok := server.Meta["userAuthRequired"].(bool); ok && userAuthRequired {
			// Check if required env vars are provided
			// For now, we'll be lenient and just log warnings
		}
	}

	// Determine connection type and sidecar configuration
	connectionType := models.ConnectionTypeStreamableHttp
	var sidecarConfig *models.SidecarConfig

	// For non-remote servers (those with stdio packages), always create sidecars
	// The MCP inside the sidecar will use HTTP streamable-HTTP transport
	logging.AdapterLogger.Info("Checking server %s for sidecar creation (hasStdio: %v, uyuni: %v, bugzilla: %v)",
		server.Name, as.hasStdioPackage(server), strings.Contains(server.Name, "uyuni"), strings.Contains(server.Name, "bugzilla"))

	if as.hasStdioPackage(server) || strings.Contains(server.Name, "uyuni") || strings.Contains(server.Name, "bugzilla") {
		logging.AdapterLogger.Info("Will create sidecar for server %s", server.Name)

		// Extract sidecar configuration from server metadata
		extractedConfig := as.getSidecarConfig(server)
		if extractedConfig != nil {
			sidecarConfig = extractedConfig
			// Process template variables in the command
			processedConfig := as.processCommandTemplates(sidecarConfig, server)
			sidecarConfig = processedConfig

			// Check if this is an HTTP remote server (no sidecar needed)
			if sidecarConfig.CommandType == "http" {
				connectionType = models.ConnectionTypeRemoteHttp
				logging.AdapterLogger.Success("Created HTTP remote config for server %s", server.Name)
			} else {
				connectionType = models.ConnectionTypeStreamableHttp
				logging.AdapterLogger.Success("Created sidecar config with commandType: %s", sidecarConfig.CommandType)
			}
		} else {
			// Fallback: try to create a generic sidecar configuration
			sidecarConfig = &models.SidecarConfig{
				CommandType: "npx",
				Command:     "npx",
				Args:        []string{"-y", "@modelcontextprotocol/server-everything"},
				Port:        0, // Will be allocated dynamically
			}
			connectionType = models.ConnectionTypeStreamableHttp
			logging.AdapterLogger.Info("Created fallback sidecar config")
		}
	} else {
		// For remote servers, check for HTTP sidecar config first
		extractedConfig := as.getSidecarConfig(server)
		if extractedConfig != nil && extractedConfig.CommandType == "http" {
			// Process template variables in the command (URL)
			processedConfig := as.processCommandTemplates(extractedConfig, server)
			sidecarConfig = processedConfig
			connectionType = models.ConnectionTypeRemoteHttp
			logging.AdapterLogger.Success("Created HTTP remote config for server %s", server.Name)
		} else {
			// For other remote servers, use RemoteHttp if they have a URL
			if server.URL != "" {
				connectionType = models.ConnectionTypeRemoteHttp
				logging.AdapterLogger.Success("Created remote HTTP config for server %s", server.Name)
			} else {
				fmt.Printf("ADAPTER_SERVICE_DEBUG: Will NOT create adapter for server %s (no URL)\n", server.Name)
				return nil, fmt.Errorf("server %s has no URL for remote connection", server.Name)
			}
		}
	}

	// Generate a secure token for the adapter
	token := as.generateSecureToken()

	// Determine remote URL based on connection type
	remoteUrl := server.URL // Default to server URL
	if connectionType == models.ConnectionTypeRemoteHttp && sidecarConfig != nil {
		// For HTTP remote connections, use the command as the remote URL
		remoteUrl = sidecarConfig.Command
	}

	// Determine initial status
	initialStatus := models.AdapterLifecycleStatusNotReady
	if connectionType == models.ConnectionTypeRemoteHttp {
		initialStatus = models.AdapterLifecycleStatusReady // HTTP remotes are ready immediately
	}

	// Create adapter data
	adapterData := &models.AdapterData{
		Name:                 name,
		ConnectionType:       connectionType,
		Status:               initialStatus,
		EnvironmentVariables: envVars,   // Use the provided environment variables
		RemoteUrl:            remoteUrl, // Use appropriate remote URL
		URL:                  fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s/mcp", name),
		SidecarConfig:        sidecarConfig,
	}

	// Create MCP client configuration based on connection type
	if connectionType == models.ConnectionTypeRemoteHttp {
		// For RemoteHttp adapters, set direct URL-based configuration
		adapterData.MCPClientConfig = models.MCPClientConfig{
			MCPServers: map[string]models.MCPServerConfig{
				name: {
					URL: remoteUrl, // Direct connection to remote MCP server
					Headers: map[string]string{
						"Authorization": fmt.Sprintf("Bearer %s", token),
					},
				},
			},
		}
	} else if connectionType == models.ConnectionTypeStreamableHttp {
		// For StreamableHttp adapters (proxy-based), set URL-based configuration
		// We store the standard MCP client config, but the handlers will provide multiple formats
		adapterData.MCPClientConfig = models.MCPClientConfig{
			MCPServers: map[string]models.MCPServerConfig{
				name: {
					URL: fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s/mcp", name),
					Headers: map[string]string{
						"Authorization": fmt.Sprintf("Bearer %s", token),
					},
				},
			},
		}
	} else {
		// For stdio-based adapters, set command-based configuration
		adapterData.MCPClientConfig = models.MCPClientConfig{
			MCPServers: map[string]models.MCPServerConfig{
				name: {
					Command: "remote",
					Args: []string{
						name,
						fmt.Sprintf("http://localhost:8911/api/v1/adapters/%s/mcp", name),
						"--header",
						fmt.Sprintf("Authorization: Bearer %s", token),
					},
					Env: map[string]string{
						"AUTH_TOKEN": token,
					},
				},
			},
		}
	}

	// Set up authentication configuration
	adapterData.Authentication = &models.AdapterAuthConfig{
		Required: true,
		Type:     "bearer",
		BearerToken: &models.BearerTokenConfig{
			Token:   token,
			Dynamic: false,
		},
	}

	// Create adapter resource
	adapter := &models.AdapterResource{}
	adapter.Create(*adapterData, userID, time.Now())

	// Store adapter
	if err := as.store.Create(ctx, *adapter); err != nil {
		return nil, fmt.Errorf("failed to store adapter: %w", err)
	}

	// Deploy sidecar if needed
	logging.AdapterLogger.Info("ADAPTER_SERVICE: Checking sidecar deployment - SidecarConfig: %v, ConnectionType: %v", adapter.SidecarConfig != nil, adapter.ConnectionType)
	if adapter.SidecarConfig != nil && adapter.ConnectionType == models.ConnectionTypeStreamableHttp {
		logging.AdapterLogger.Info("Sidecar deployment needed for adapter %s (SidecarConfig: %+v)", adapter.ID, adapter.SidecarConfig)
		if as.sidecarManager == nil {
			logging.AdapterLogger.Error("SidecarManager is nil, cannot deploy sidecar for adapter %s", adapter.ID)
			// Clean up the adapter since sidecar deployment is required
			as.store.Delete(ctx, adapter.ID)
			return nil, fmt.Errorf("sidecar manager not available for adapter deployment")
		} else {
			logging.AdapterLogger.Info("Deploying sidecar for adapter %s", adapter.ID)
			if err := as.sidecarManager.DeploySidecar(ctx, *adapter); err != nil {
				logging.AdapterLogger.Error("Sidecar deployment failed for adapter %s: %v", adapter.ID, err)
				// Set status to error before cleanup
				adapter.Status = models.AdapterLifecycleStatusError
				as.store.Update(ctx, *adapter) // Update status before deletion
				// If sidecar deployment fails, we should clean up the adapter
				as.store.Delete(ctx, adapter.ID)
				return nil, fmt.Errorf("failed to deploy sidecar: %w", err)
			}
			logging.AdapterLogger.Success("Sidecar deployment successful for adapter %s", adapter.ID)
			logging.AdapterLogger.Info("Waiting for sidecar to be ready before capability discovery...")

			// Wait longer for the sidecar to be fully ready (MCP servers need time to start)
			time.Sleep(10 * time.Second)

			// Discover actual capabilities from the deployed sidecar
			logging.AdapterLogger.Info("Starting capability discovery for adapter %s", adapter.ID)
			if err := as.discoverCapabilitiesFromSidecar(ctx, adapter); err != nil {
				logging.AdapterLogger.Warn("Failed to discover capabilities from sidecar for adapter %s: %v", adapter.ID, err)
				// Set status to error if capability discovery fails
				adapter.Status = models.AdapterLifecycleStatusError
				// Don't fail the entire creation - just log the warning
				// The adapter will still work with basic capabilities
			} else {
				logging.AdapterLogger.Success("Successfully discovered capabilities from sidecar for adapter %s", adapter.ID)
				// Set status to ready if capability discovery succeeds
				adapter.Status = models.AdapterLifecycleStatusReady
			}

			// Check sidecar health and update status accordingly
			if err := as.checkAndUpdateSidecarHealth(ctx, adapter); err != nil {
				logging.AdapterLogger.Warn("Failed to check sidecar health for adapter %s: %v", adapter.ID, err)
				// Continue anyway - health check failure doesn't prevent adapter creation
			}

			// Update the stored adapter with the allocated port, discovered capabilities, and status
			if err := as.store.Update(ctx, *adapter); err != nil {
				logging.AdapterLogger.Error("Failed to update adapter in store: %v", err)
				return nil, fmt.Errorf("failed to update adapter: %w", err)
			}
		}
	} else {
		logging.AdapterLogger.Info("ADAPTER_SERVICE: Sidecar deployment NOT needed - SidecarConfig nil: %v, ConnectionType: %v", adapter.SidecarConfig == nil, adapter.ConnectionType)
		// For non-sidecar adapters, set status to ready immediately
		adapter.Status = models.AdapterLifecycleStatusReady

		// Update the stored adapter with the ready status
		if err := as.store.Update(ctx, *adapter); err != nil {
			logging.AdapterLogger.Error("Failed to update adapter status in store: %v", err)
			return nil, fmt.Errorf("failed to update adapter: %w", err)
		}
	}

	logging.AdapterLogger.Success("CreateAdapter completed successfully for adapter %s", adapter.ID)
	return adapter, nil
}

// hasStdioPackage checks if the server has stdio packages
func (as *AdapterService) hasStdioPackage(server *models.MCPServer) bool {
	for _, pkg := range server.Packages {
		if pkg.RegistryType == "stdio" || pkg.Transport.Type == "stdio" {
			return true
		}
	}
	return false
}

// generateSecureToken generates a cryptographically secure random token
func (as *AdapterService) generateSecureToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		logging.AdapterLogger.Warn("Failed to generate secure token, falling back to timestamp: %v", err)
		// Fallback to timestamp-based token
		return fmt.Sprintf("token-%d-%s", time.Now().Unix(), "fallback")
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
