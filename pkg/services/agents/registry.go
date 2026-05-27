package agents

import "sync"

// Registry holds the set of AgentProtocol implementations the proxy knows
// about. New protocols register themselves at process start via init()
// functions in their own file; downstream code looks them up by name.
type Registry struct {
	mu        sync.RWMutex
	protocols map[string]AgentProtocol
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{protocols: make(map[string]AgentProtocol)}
}

// Register adds impl under name. If a protocol is already registered under
// the same name, it is replaced — registration is last-write-wins by design
// so tests can swap in fakes.
func (r *Registry) Register(name string, impl AgentProtocol) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.protocols[name] = impl
}

// Get returns the protocol registered under name, or (nil, false).
func (r *Registry) Get(name string) (AgentProtocol, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.protocols[name]
	return p, ok
}

// Names returns the set of registered protocol names in unspecified order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.protocols))
	for n := range r.protocols {
		names = append(names, n)
	}
	return names
}

// DefaultRegistry is the process-wide registry. Built-in protocols
// register themselves into it via init(); new protocols added in
// Phase 2 should follow the same pattern.
var DefaultRegistry = NewRegistry()
