package agents

import (
	"context"
	"errors"
	"net/http"
)

// ProtocolNameSmartAgents is the wire identifier for the SmartAgents
// protocol. Must match plugins.ServiceTypeSmartAgents — both describe the
// same string seen by external HTTP clients ("/plugins/services/type/{name}",
// service registration payloads). When you rename one, rename the other.
const ProtocolNameSmartAgents = "smartagents"

// SmartAgentsConfig holds the env-var-driven settings for the SmartAgents
// remote service the plugin manager talks to. internal/config consumes
// this via SmartAgentsConfigFromEnv to populate its PluginServicesConfig
// without referencing smartagents-specific env var names directly.
type SmartAgentsConfig struct {
	Enabled bool
	URL     string
	Timeout string
}

// SmartAgentsConfigFromEnv returns the SmartAgents defaults overlaid with
// SMARTAGENTS_* env vars. The getEnv / getEnvBool helpers are injected to
// keep agents/ from depending on internal/config (which would cycle).
func SmartAgentsConfigFromEnv(
	getEnv func(key, def string) string,
	getEnvBool func(key string, def bool) bool,
) SmartAgentsConfig {
	return SmartAgentsConfig{
		Enabled: getEnvBool("SMARTAGENTS_ENABLED", true),
		URL:     getEnv("SMARTAGENTS_URL", "http://localhost:8910"),
		Timeout: getEnv("SMARTAGENTS_TIMEOUT", "30s"),
	}
}

// SmartAgentsProtocol is the Phase 1 stub implementation of AgentProtocol
// for SmartAgents. It preserves the existing service-type behavior:
// registration still flows through the generic plugin manager, request
// handling is not yet protocol-aware (returns not-implemented), ACL is
// allow-all.
type SmartAgentsProtocol struct{}

// NewSmartAgentsProtocol returns the default SmartAgents protocol stub.
func NewSmartAgentsProtocol() *SmartAgentsProtocol { return &SmartAgentsProtocol{} }

// Name returns ProtocolNameSmartAgents.
func (*SmartAgentsProtocol) Name() string { return ProtocolNameSmartAgents }

// Capabilities returns nil. Phase 1 keeps routing on the per-registration
// ServiceCapability list owned by the plugin manager; Phase 2 fills this
// in when the Agent CRD starts publishing capability sets.
func (*SmartAgentsProtocol) Capabilities() []Capability { return nil }

// HandleRequest is a Phase 1 stub. Phase 2's Agent CRD controller fills
// this in with real per-protocol dispatch.
func (*SmartAgentsProtocol) HandleRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	return nil, errors.New("smartagents protocol: request handling not implemented in Phase 1")
}

// EnforceACL is a Phase 1 stub: allow-all. Phase 2 wires this to the
// user/group store.
func (*SmartAgentsProtocol) EnforceACL(ctx context.Context, subject, action string) error {
	return nil
}

func init() {
	DefaultRegistry.Register(ProtocolNameSmartAgents, NewSmartAgentsProtocol())
}
