package services

import (
	"context"
	"fmt"

	"suse-ai-up/pkg/logging"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/services"
)

// GetAdapter gets an adapter by ID with permission checking
func (as *AdapterService) GetAdapter(ctx context.Context, userID, adapterID string, userGroupService *services.UserGroupService) (*models.AdapterResource, error) {
	adapter, err := as.store.Get(ctx, adapterID)
	if err != nil {
		return nil, err
	}

	// Check if user can access this adapter
	if adapter.CreatedBy != userID {
		// Check admin permissions
		if userGroupService != nil {
			if canManage, err := userGroupService.CanManageGroups(ctx, userID); err == nil && canManage {
				// Admin can access any adapter
			} else {
				return nil, fmt.Errorf("adapter not found")
			}
		} else {
			return nil, fmt.Errorf("adapter not found")
		}
	}

	return adapter, nil
}

// ListAdapters lists adapters with permission-based filtering
func (as *AdapterService) ListAdapters(ctx context.Context, userID string, userGroupService *services.UserGroupService) ([]models.AdapterResource, error) {
	// Check if user is admin (can see all adapters)
	if userGroupService != nil {
		if canManage, err := userGroupService.CanManageGroups(ctx, userID); err == nil && canManage {
			return as.store.ListAll(ctx)
		}
	}

	// Regular users only see their own adapters
	return as.store.List(ctx, userID)
}

// UpdateAdapter updates an adapter
func (as *AdapterService) UpdateAdapter(ctx context.Context, userID string, adapter models.AdapterResource) error {
	// Check if adapter belongs to user
	existing, err := as.store.Get(ctx, adapter.ID)
	if err != nil {
		return err
	}

	if existing.CreatedBy != userID {
		return fmt.Errorf("adapter not found")
	}

	// Update the adapter
	adapter.CreatedBy = userID // Ensure user ownership
	return as.store.Update(ctx, adapter)
}

// DeleteAdapter deletes an adapter and its associated resources
func (as *AdapterService) DeleteAdapter(ctx context.Context, userID, adapterID string) error {
	logging.AdapterLogger.Info("DeleteAdapter called for adapter %s by user %s", adapterID, userID)

	// Get adapter before deletion to check if it has sidecar resources
	adapter, err := as.store.Get(ctx, adapterID)
	if err != nil {
		logging.AdapterLogger.Error("Failed to get adapter %s: %v", adapterID, err)
	} else if adapter != nil {
		logging.AdapterLogger.Info("Found adapter %s with connection type: %s", adapterID, adapter.ConnectionType)

		// If this is a sidecar adapter (StreamableHttp with sidecar config), clean up the sidecar resources
		if adapter.ConnectionType == models.ConnectionTypeStreamableHttp && adapter.SidecarConfig != nil {
			if as.sidecarManager == nil {
				logging.AdapterLogger.Warn("SidecarManager is nil, cannot cleanup sidecar for adapter %s", adapterID)
			} else {
				logging.AdapterLogger.Info("Cleaning up sidecar for adapter %s", adapterID)
				if cleanupErr := as.sidecarManager.CleanupSidecar(ctx, adapterID); cleanupErr != nil {
					// Log the error but don't fail the adapter deletion
					logging.AdapterLogger.Warn("Failed to cleanup sidecar for adapter %s: %v", adapterID, cleanupErr)
				} else {
					logging.AdapterLogger.Success("Successfully initiated sidecar cleanup for adapter %s", adapterID)
				}
			}
		} else {
			logging.AdapterLogger.Info("Adapter %s is not a sidecar adapter (type: %s), skipping sidecar cleanup", adapterID, adapter.ConnectionType)
		}
	} else {
		logging.AdapterLogger.Warn("Adapter %s not found in store", adapterID)
	}

	// Delete the adapter from store
	if err := as.store.Delete(ctx, adapterID); err != nil {
		logging.AdapterLogger.Error("Failed to delete adapter %s from store: %v", adapterID, err)
		return fmt.Errorf("failed to delete adapter from store: %w", err)
	}

	logging.AdapterLogger.Success("Successfully deleted adapter %s", adapterID)
	return nil
}
