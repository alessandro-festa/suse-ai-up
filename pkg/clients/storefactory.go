package clients

// StoreConfig configures the store factory. Phase 1 only needs the adapter
// file path; Phase 2 will extend this with the fields a controller-runtime
// manager needs (REST config, namespace, scheme) without changing the
// downstream Stores surface.
type StoreConfig struct {
	// AdapterFilePath is the on-disk path for the file-backed adapter store.
	// Empty defaults to "/tmp/adapters.json" to preserve Phase 1 behavior.
	AdapterFilePath string
}

// Stores bundles every store the bootstrap layer needs. Phase 1 returns the
// existing file- and memory-backed implementations; Phase 2 will swap in
// controller-runtime-backed stores without changing this surface or any
// callsite past bootstrap.
type Stores struct {
	Adapter  AdapterResourceStore
	Registry MCPServerStore
	User     UserStore
	Group    GroupStore
}

// New constructs the default Phase 1 store set: a file-backed adapter store
// and in-memory stores for everything else. Matches the wiring previously
// inlined in internal/bootstrap/bootstrap.go.
func New(cfg StoreConfig) *Stores {
	adapterPath := cfg.AdapterFilePath
	if adapterPath == "" {
		adapterPath = "/tmp/adapters.json"
	}
	return &Stores{
		Adapter:  NewFileAdapterStore(adapterPath),
		Registry: NewInMemoryMCPServerStore(),
		User:     NewInMemoryUserStore(),
		Group:    NewInMemoryGroupStore(),
	}
}
