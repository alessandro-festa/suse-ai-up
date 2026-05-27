package virtualmcp

import (
	"context"
	"errors"
	"sync"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

// RouteRegistry exposes virtual-MCP route composition: assembling a single
// virtual MCP server view from multiple registered adapters/backends.
//
// The reader split is preserved so handlers that only need to look up
// routes can depend on this narrower interface; writers depend on
// RouteStore below.
type RouteRegistry interface {
	// ListRoutes returns every composed virtual route currently known to
	// the registry.
	ListRoutes() []models.MCPServer

	// GetRoute looks up a single composed virtual route by ID. Returns
	// (nil, false) when no route with that ID is registered.
	GetRoute(id string) (*models.MCPServer, bool)
}

// RouteStore extends RouteRegistry with the mutation methods the
// VirtualMCPRouteReconciler needs to publish composed routes. §2.4 will
// share whichever implementation the HTTP shim uses; for now the manager
// binary owns an InMemoryRouteStore.
type RouteStore interface {
	RouteRegistry
	UpsertRoute(route *models.MCPServer) error
	DeleteRoute(id string) error
}

// NewNoopRouteRegistry returns a RouteRegistry that always reports zero
// routes. Kept for compatibility with the original Phase 1 stub; new code
// should use NewInMemoryRouteStore.
func NewNoopRouteRegistry() RouteRegistry { return noopRouteRegistry{} }

type noopRouteRegistry struct{}

func (noopRouteRegistry) ListRoutes() []models.MCPServer               { return nil }
func (noopRouteRegistry) GetRoute(id string) (*models.MCPServer, bool) { return nil, false }

// InMemoryRouteStore is the default RouteStore implementation. It mirrors
// pkg/clients.InMemoryMCPServerStore's shape — map + RWMutex — but holds
// composed routes, not registry entries.
type InMemoryRouteStore struct {
	mu     sync.RWMutex
	routes map[string]*models.MCPServer
}

// NewInMemoryRouteStore returns an empty InMemoryRouteStore.
func NewInMemoryRouteStore() *InMemoryRouteStore {
	return &InMemoryRouteStore{routes: map[string]*models.MCPServer{}}
}

// ListRoutes returns a snapshot copy of every route currently in the
// store. The snapshot prevents callers from mutating store state through
// the returned slice.
func (s *InMemoryRouteStore) ListRoutes() []models.MCPServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.MCPServer, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, *r)
	}
	return out
}

// GetRoute returns a copy of the route with the given ID, or (nil, false).
func (s *InMemoryRouteStore) GetRoute(id string) (*models.MCPServer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.routes[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// UpsertRoute creates-or-replaces the route keyed by route.ID.
func (s *InMemoryRouteStore) UpsertRoute(route *models.MCPServer) error {
	if route == nil {
		return errors.New("virtualmcp: UpsertRoute called with nil route")
	}
	if route.ID == "" {
		return errors.New("virtualmcp: UpsertRoute requires route.ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *route
	s.routes[route.ID] = &cp
	return nil
}

// DeleteRoute removes the route with the given ID. Missing IDs are not
// an error — reconcilers call DeleteRoute defensively on every NotFound
// without needing to know whether a route was previously registered.
func (s *InMemoryRouteStore) DeleteRoute(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.routes, id)
	return nil
}

// Catalog is a flattened tool/resource/prompt listing for a single source
// (Adapter or MCPServer) as seen by VirtualMCPRouteReconciler.
type Catalog struct {
	Tools     []CatalogEntry
	Resources []CatalogEntry
	Prompts   []CatalogEntry
}

// CatalogEntry is one entry in a source's Catalog. Only the name is
// carried today — the reconciler matches names against selectors and
// outputs renamed entries — but the struct exists so §2.4 can add
// description / schema fields without changing the interface shape.
type CatalogEntry struct {
	Name string
}

// CapabilityProvider supplies per-source catalogs to
// VirtualMCPRouteReconciler. The reconciler calls AdapterCatalog or
// MCPServerCatalog for each source referenced in a VirtualMCPRoute;
// implementations that cannot serve a catalog (e.g. the NoOp shipped in
// §2.3c) return ErrCatalogUnavailable so the reconciler can degrade
// gracefully instead of failing the route.
type CapabilityProvider interface {
	AdapterCatalog(ctx context.Context, namespace, name string) (*Catalog, error)
	MCPServerCatalog(ctx context.Context, namespace, name string) (*Catalog, error)
}

// ErrCatalogUnavailable signals that the provider has no catalog data
// for the requested source. Treated by the reconciler as "degrade,
// don't fail" — see VirtualMCPRouteReconciler.Reconcile.
var ErrCatalogUnavailable = errors.New("virtualmcp: catalog unavailable")

// NewNoOpCapabilityProvider returns a provider that always returns
// ErrCatalogUnavailable. Used by §2.3c so VirtualMCPRoutes ship with
// empty ResolvedEntries and a clear "CatalogUnavailable" condition
// until §2.4 wires in the real provider (backed by either the live
// capability cache or new status fields on Adapter/MCPServer).
func NewNoOpCapabilityProvider() CapabilityProvider { return noOpCapabilityProvider{} }

type noOpCapabilityProvider struct{}

func (noOpCapabilityProvider) AdapterCatalog(context.Context, string, string) (*Catalog, error) {
	return nil, ErrCatalogUnavailable
}

func (noOpCapabilityProvider) MCPServerCatalog(context.Context, string, string) (*Catalog, error) {
	return nil, ErrCatalogUnavailable
}
