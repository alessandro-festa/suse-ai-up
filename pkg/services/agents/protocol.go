// Package agents owns every agent-to-agent protocol the proxy can route
// requests to. Phase 1 ships the original "smartagents" protocol as a stub
// implementation registered with the default registry; Phase 2 (Agent CRD)
// ships real implementations and additional protocols (A2A, custom)
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

// MCPDispatcher dispatches a JSON-RPC body to a named Adapter's
// upstream. Protocol implementations use this to invoke source tools
// referenced by Agent.Spec.Tools[]. *handlers.AdapterHandler satisfies
// this — the interface is defined here so the agents package doesn't
// have to import internal/handlers (which would cycle).
type MCPDispatcher interface {
	ProxyMCPToAdapter(ctx context.Context, adapterID, userID string, body []byte, headers http.Header) (int, string, []byte, error)
}

// InvocationContext bundles the per-request information a protocol
// implementation needs to enforce its tool ACL and dispatch downstream
// calls. Built by the HTTP handler before delegating to the protocol.
type InvocationContext struct {
	// UserID identifies the authenticated caller (set by
	// auth.UserAuthMiddleware before the handler ran).
	UserID string

	// Agent is the in-memory projection of the Agent CR. Carries
	// Spec.Tools[] (flattened to ToolRefs) so the protocol can enforce
	// the resource-level ACL before invoking the dispatcher.
	Agent *RegisteredAgent

	// Dispatcher is the MCP transport for downstream calls into source
	// Adapters. May be nil in tests that don't exercise dispatch.
	Dispatcher MCPDispatcher
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
	// The protocol writes the response directly to w. May invoke
	// ic.Dispatcher for downstream MCP calls; MUST enforce ic.Agent.Tools
	// (resource-level ACL — see Agent.Spec.Tools) before doing so.
	HandleRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, ic InvocationContext)

	// EnforceACL is the access-control hook. Returns nil when subject is
	// allowed to perform action; non-nil when denied. Phase 1 default is
	// allow-all; Phase 2 wires this to the user/group store.
	EnforceACL(ctx context.Context, subject, action string) error
}
