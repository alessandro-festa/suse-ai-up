package virtualmcp

import "github.com/SUSE/suse-ai-up/pkg/models"

// RouteRegistry exposes virtual-MCP route composition: assembling a single
// virtual MCP server view from multiple registered adapters/backends.
//
// Phase 1 ships a no-op implementation; Phase 2's VirtualMCPRoute CRD
// controller fills this in. The interface lives in the discovery package
// from day one so the operator rewrite has an obvious landing spot and so
// downstream callers can be wired against a stable type without churning
// when the real implementation arrives.
type RouteRegistry interface {
	// ListRoutes returns every composed virtual route currently known to
	// the registry.
	ListRoutes() []models.MCPServer

	// GetRoute looks up a single composed virtual route by ID. Returns
	// (nil, false) when no route with that ID is registered.
	GetRoute(id string) (*models.MCPServer, bool)
}

// NewNoopRouteRegistry returns a RouteRegistry that always reports zero
// routes. Used as the Phase 1 default until the VirtualMCPRoute controller
// is wired in.
func NewNoopRouteRegistry() RouteRegistry { return noopRouteRegistry{} }

type noopRouteRegistry struct{}

func (noopRouteRegistry) ListRoutes() []models.MCPServer            { return nil }
func (noopRouteRegistry) GetRoute(id string) (*models.MCPServer, bool) { return nil, false }
