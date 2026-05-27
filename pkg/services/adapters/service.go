package services

import (
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/mcp"
	"github.com/SUSE/suse-ai-up/pkg/proxy"
)

// AdapterService manages adapters for remote MCP servers
type AdapterService struct {
	store               clients.AdapterResourceStore
	registryStore       clients.MCPServerStore
	capabilityDiscovery *mcp.CapabilityDiscoveryService
	sidecarManager      *proxy.SidecarManager
}

// NewAdapterService creates a new adapter service
func NewAdapterService(store clients.AdapterResourceStore, registryStore clients.MCPServerStore, sidecarManager *proxy.SidecarManager) *AdapterService {
	return &AdapterService{
		store:               store,
		registryStore:       registryStore,
		capabilityDiscovery: mcp.NewCapabilityDiscoveryService(),
		sidecarManager:      sidecarManager,
	}
}
