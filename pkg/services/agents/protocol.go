// Package agents owns every agent-to-agent protocol the proxy can route
// requests to. Phase 1 ships the original "smartagents" protocol as a stub
// implementation registered with the default registry; Phase 2 (Agent CRD)
// will ship real implementations and additional protocols (A2A, custom)
// without touching the generic plugin manager.
package agents

import (
	"context"
	"net/http"
)

// Capability describes one routable surface a protocol exposes.
type Capability struct {
	Path        string
	Methods     []string
	Description string
}

// AgentProtocol is the contract every agent-to-agent protocol must
// satisfy. The interface intentionally separates description from
// execution so Phase 2 controllers can introspect and route without
// loading protocol-specific logic into the generic plugin manager.
type AgentProtocol interface {
	// Name returns the protocol's wire identifier (e.g. "smartagents",
	// "a2a"). Must match the ServiceType strings used over the HTTP
	// plugins API so external clients can address it.
	Name() string

	// Capabilities returns the routable surfaces this protocol exposes.
	// Phase 1 implementations may return an empty slice; routing today
	// flows through the per-registration ServiceCapability list on the
	// plugin manager.
	Capabilities() []Capability

	// HandleRequest dispatches an inbound HTTP request to the protocol.
	// Phase 1 implementations return a not-implemented error; Phase 2's
	// Agent CRD controller fills this in.
	HandleRequest(ctx context.Context, req *http.Request) (*http.Response, error)

	// EnforceACL is the access-control hook. Returns nil when subject is
	// allowed to perform action; non-nil when denied. Phase 1 default is
	// allow-all; Phase 2 wires this to the user/group store.
	EnforceACL(ctx context.Context, subject, action string) error
}
