package services

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"suse-ai-up/pkg/logging"
	"suse-ai-up/pkg/mcp"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/services"
)

// SyncAdapterCapabilities syncs capabilities for an adapter
func (as *AdapterService) SyncAdapterCapabilities(ctx context.Context, userID, adapterID string, userGroupService *services.UserGroupService) error {
	// Get adapter
	adapter, err := as.GetAdapter(ctx, userID, adapterID, userGroupService)
	if err != nil {
		return err
	}

	// Re-discover capabilities
	if err := as.discoverCapabilities(ctx, &adapter.AdapterData); err != nil {
		return fmt.Errorf("failed to sync capabilities: %w", err)
	}

	// Update adapter
	return as.store.Update(ctx, *adapter)
}

// CheckAdapterHealth checks and updates the health status of an adapter
func (as *AdapterService) CheckAdapterHealth(ctx context.Context, userID, adapterID string, userGroupService *services.UserGroupService) error {
	// Get adapter
	adapter, err := as.GetAdapter(ctx, userID, adapterID, userGroupService)
	if err != nil {
		return err
	}

	// Check and update sidecar health
	if err := as.checkAndUpdateSidecarHealth(ctx, adapter); err != nil {
		return fmt.Errorf("failed to check adapter health: %w", err)
	}

	return nil
}

// discoverCapabilities discovers MCP capabilities for an adapter
// discoverCapabilities sets basic capabilities for adapters without sidecars
func (as *AdapterService) discoverCapabilities(ctx context.Context, adapterData *models.AdapterData) error {
	// For adapters without sidecars (remote connections), set basic capabilities
	adapterData.MCPFunctionality = &models.MCPFunctionality{
		ServerInfo: models.MCPServerInfo{
			Name:    adapterData.Name,
			Version: "1.0.0",
		},
		Tools:         []models.MCPTool{},
		Resources:     []models.MCPResource{},
		Prompts:       []models.MCPPrompt{},
		LastRefreshed: time.Now(),
	}

	return nil
}

// discoverCapabilitiesFromSidecar discovers capabilities from a deployed sidecar
func (as *AdapterService) discoverCapabilitiesFromSidecar(ctx context.Context, adapter *models.AdapterResource) error {
	logging.AdapterLogger.Info("Starting capability discovery for sidecar adapter %s", adapter.ID)

	// Use the internal sidecar service URL instead of the external proxy URL
	sidecarServiceURL := fmt.Sprintf("http://mcp-sidecar-%s.suseai.svc.cluster.local:8000", adapter.ID)
	logging.AdapterLogger.Info("Using sidecar service URL: %s", sidecarServiceURL)

	// For sidecar communication, we don't need authentication since it's internal cluster communication
	auth := (*models.AdapterAuthConfig)(nil) // No auth needed for internal service calls

	// First, try a health check to see if the sidecar is responding
	if err := as.healthCheckSidecar(ctx, sidecarServiceURL); err != nil {
		logging.AdapterLogger.Warn("Sidecar health check failed for adapter %s: %v", adapter.ID, err)
		// Continue with discovery attempt anyway
	} else {
		logging.AdapterLogger.Info("Sidecar health check passed for adapter %s", adapter.ID)
	}

	// Use the capability discovery service to get real tools with retry logic
	logging.AdapterLogger.Info("Calling MCP capability discovery service for adapter %s", adapter.ID)
	capabilities, err := as.discoverCapabilitiesWithRetry(ctx, sidecarServiceURL, auth)
	if err != nil {
		logging.AdapterLogger.Warn("MCP capability discovery failed for adapter %s: %v", adapter.ID, err)

		// Try to get basic server info as fallback
		logging.AdapterLogger.Info("Attempting to get basic server info as fallback for adapter %s", adapter.ID)
		serverInfo, infoErr := as.getBasicServerInfo(ctx, sidecarServiceURL, auth)
		if infoErr != nil {
			logging.AdapterLogger.Warn("Basic server info discovery also failed for adapter %s: %v", adapter.ID, infoErr)
			// Set minimal capabilities
			adapter.MCPFunctionality = &models.MCPFunctionality{
				ServerInfo: models.MCPServerInfo{
					Name:    adapter.Name,
					Version: "1.0.0",
				},
				Tools:         []models.MCPTool{},
				Resources:     []models.MCPResource{},
				Prompts:       []models.MCPPrompt{},
				LastRefreshed: time.Now(),
			}
			logging.AdapterLogger.Info("Set minimal capabilities for adapter %s due to discovery failures", adapter.ID)
			return nil
		}

		// Set capabilities with discovered server info but no tools
		adapter.MCPFunctionality = &models.MCPFunctionality{
			ServerInfo:    *serverInfo,
			Tools:         []models.MCPTool{},
			Resources:     []models.MCPResource{},
			Prompts:       []models.MCPPrompt{},
			LastRefreshed: time.Now(),
		}
		logging.AdapterLogger.Info("Set server info capabilities for adapter %s (%d tools found via basic discovery)", adapter.ID, len(capabilities.Tools))
		return nil
	}

	// Update adapter with discovered capabilities
	adapter.MCPFunctionality = capabilities
	logging.AdapterLogger.Success("Successfully discovered capabilities for adapter %s: %d tools, %d resources, %d prompts",
		adapter.ID, len(capabilities.Tools), len(capabilities.Resources), len(capabilities.Prompts))

	return nil
}

// discoverCapabilitiesWithRetry attempts capability discovery with exponential backoff retry
func (as *AdapterService) discoverCapabilitiesWithRetry(ctx context.Context, serverURL string, auth *models.AdapterAuthConfig) (*models.MCPFunctionality, error) {
	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt) * baseDelay
			logging.AdapterLogger.Info("Retrying capability discovery in %v (attempt %d/%d)", delay, attempt+1, maxRetries)
			time.Sleep(delay)
		}

		capabilities, err := mcp.NewCapabilityDiscoveryService().DiscoverCapabilities(ctx, serverURL, auth)
		if err == nil {
			return capabilities, nil
		}

		logging.AdapterLogger.Warn("Capability discovery attempt %d/%d failed: %v", attempt+1, maxRetries, err)

		// If this is the last attempt, return the error
		if attempt == maxRetries-1 {
			return nil, err
		}
	}

	// This should never be reached, but just in case
	return nil, fmt.Errorf("capability discovery failed after %d attempts", maxRetries)
}

// healthCheckSidecar performs a basic health check on the sidecar
func (as *AdapterService) healthCheckSidecar(ctx context.Context, serverURL string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// getBasicServerInfo attempts to get basic server information
func (as *AdapterService) getBasicServerInfo(ctx context.Context, serverURL string, auth *models.AdapterAuthConfig) (*models.MCPServerInfo, error) {
	// For internal cluster communication, create client without auth
	client := mcp.NewMCPClient(serverURL, nil)

	if err := client.Initialize(ctx); err != nil {
		return nil, err
	}
	defer client.Close()

	return client.GetServerInfo(ctx)
}

// checkAndUpdateSidecarHealth checks the health of sidecar deployments and updates adapter status
func (as *AdapterService) checkAndUpdateSidecarHealth(ctx context.Context, adapter *models.AdapterResource) error {
	if adapter.SidecarConfig == nil || adapter.ConnectionType != models.ConnectionTypeStreamableHttp {
		// Non-sidecar adapters are always ready
		return nil
	}

	if as.sidecarManager == nil {
		logging.AdapterLogger.Warn("SidecarManager not available for health check of adapter %s", adapter.ID)
		return nil
	}

	// Check if sidecar is healthy (this would need to be implemented in SidecarManager)
	// For now, we'll check if we can reach the sidecar service
	sidecarServiceURL := fmt.Sprintf("http://mcp-sidecar-%s.suseai.svc.cluster.local:8000", adapter.ID)

	healthy, err := as.isSidecarHealthy(ctx, sidecarServiceURL)
	if err != nil {
		logging.AdapterLogger.Warn("Failed to check sidecar health for adapter %s: %v", adapter.ID, err)
		// Don't change status on check failure - might be temporary network issue
		return nil
	}

	// Update status based on health
	oldStatus := adapter.Status
	if healthy {
		if adapter.Status == models.AdapterLifecycleStatusError {
			logging.AdapterLogger.Info("Sidecar for adapter %s is now healthy, changing status from error to ready", adapter.ID)
			adapter.Status = models.AdapterLifecycleStatusReady
		}
	} else {
		if adapter.Status == models.AdapterLifecycleStatusReady {
			logging.AdapterLogger.Warn("Sidecar for adapter %s is unhealthy, changing status from ready to error", adapter.ID)
			adapter.Status = models.AdapterLifecycleStatusError
		}
	}

	// Update in store if status changed
	if oldStatus != adapter.Status {
		if err := as.store.Update(ctx, *adapter); err != nil {
			logging.AdapterLogger.Error("Failed to update adapter status for %s: %v", adapter.ID, err)
			return err
		}
		logging.AdapterLogger.Info("Updated adapter %s status from %s to %s", adapter.ID, oldStatus, adapter.Status)
	}

	return nil
}

// isSidecarHealthy checks if the sidecar service is responding
func (as *AdapterService) isSidecarHealthy(ctx context.Context, serviceURL string) (bool, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", serviceURL+"/health", nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
