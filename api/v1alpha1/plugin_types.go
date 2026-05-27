/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PluginServiceType identifies the kind of plugin service registered with
// the proxy. Mirrors pkg/plugins.ServiceType so the operator and the
// existing /plugins/register HTTP path agree on wire identifiers. Adding a
// new type means updating both this enum and pkg/plugins.
// +kubebuilder:validation:Enum=smartagents;registry;virtualmcp
type PluginServiceType string

const (
	PluginServiceTypeSmartAgents PluginServiceType = "smartagents"
	PluginServiceTypeRegistry    PluginServiceType = "registry"
	PluginServiceTypeVirtualMCP  PluginServiceType = "virtualmcp"
)

// PluginCapability describes one API surface the plugin exposes through the
// proxy. The proxy uses Path/Methods to route incoming requests to the
// plugin; Description is informational only.
type PluginCapability struct {
	// Path is the API path the plugin handles, with optional wildcards
	// (e.g. "/v1/*", "/agents/*").
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// Methods are the HTTP methods the plugin accepts on Path. Empty means
	// all methods are forwarded.
	// +optional
	Methods []string `json:"methods,omitempty"`

	// Description is a free-form summary surfaced in UIs.
	// +optional
	Description string `json:"description,omitempty"`
}

// PluginHealthCheck declares how the controller probes plugin liveness.
// The controller polls Path on the plugin's ServiceURL at IntervalSeconds
// and updates Status.Healthy / Status.LastHealthCheckTime accordingly.
type PluginHealthCheck struct {
	// Path is the HTTP path to poll on the plugin's ServiceURL. Defaults
	// to "/health" when unset.
	// +optional
	Path string `json:"path,omitempty"`

	// IntervalSeconds is the polling cadence. Defaults to 30 when unset.
	// +optional
	// +kubebuilder:validation:Minimum=1
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds caps each probe. Defaults to 5 when unset.
	// +optional
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// PluginSpec is the declarative form of POST /plugins/register: a
// third-party HTTP service that extends the proxy with capabilities the
// proxy itself does not implement (smartagents runtimes, external registry
// providers, virtualmcp gateways). The PluginReconciler (#19+) projects
// this CR into the in-process PluginServiceManager so requests matching
// Capabilities[].Path are forwarded to ServiceURL.
type PluginSpec struct {
	// ServiceType selects which manager wires up this plugin.
	ServiceType PluginServiceType `json:"serviceType"`

	// ServiceURL is the base URL the proxy forwards matched requests to.
	// Must be reachable from the proxy pod (cluster-internal Service DNS
	// or a routable external URL).
	// +kubebuilder:validation:MinLength=1
	ServiceURL string `json:"serviceURL"`

	// Version is a free-form version string surfaced in UIs and matched
	// against capability filters. Plugin authors should follow semver.
	// +optional
	Version string `json:"version,omitempty"`

	// Capabilities lists the API surfaces this plugin handles. Empty
	// disables routing (the plugin remains visible to operators but
	// receives no traffic).
	// +optional
	Capabilities []PluginCapability `json:"capabilities,omitempty"`

	// HealthCheck configures the controller's liveness probe against the
	// plugin. When nil the controller uses defaults (GET /health every
	// 30s, 5s timeout).
	// +optional
	HealthCheck *PluginHealthCheck `json:"healthCheck,omitempty"`

	// Description is a free-form summary surfaced in UIs.
	// +optional
	Description string `json:"description,omitempty"`
}

// PluginPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Registered;Healthy;Unhealthy;Failed
type PluginPhase string

const (
	PluginPhasePending    PluginPhase = "Pending"
	PluginPhaseRegistered PluginPhase = "Registered"
	PluginPhaseHealthy    PluginPhase = "Healthy"
	PluginPhaseUnhealthy  PluginPhase = "Unhealthy"
	PluginPhaseFailed     PluginPhase = "Failed"
)

// Condition types set by PluginReconciler.
const (
	PluginConditionReady      = "Ready"
	PluginConditionRegistered = "Registered"
	PluginConditionHealthy    = "Healthy"
)

// PluginStatus reflects the observed state of a Plugin.
type PluginStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase PluginPhase `json:"phase,omitempty"`

	// Healthy is the last health-probe result. False means the most
	// recent probe failed or timed out.
	// +optional
	Healthy bool `json:"healthy,omitempty"`

	// LastHealthCheckTime is when the controller last completed a health
	// probe against the plugin.
	// +optional
	LastHealthCheckTime *metav1.Time `json:"lastHealthCheckTime,omitempty"`

	// LastHealthCheckMessage carries the most recent probe error string
	// when Healthy=false. Empty on success.
	// +optional
	LastHealthCheckMessage string `json:"lastHealthCheckMessage,omitempty"`

	// ResponseTimeMillis is the most recent probe latency in
	// milliseconds, surfaced for quick triage.
	// +optional
	ResponseTimeMillis int64 `json:"responseTimeMillis,omitempty"`

	// ObservedCapabilities is the capability list the controller has
	// successfully wired into the in-process PluginServiceManager. May
	// diverge from Spec.Capabilities during a rollout.
	// +optional
	ObservedCapabilities []PluginCapability `json:"observedCapabilities,omitempty"`

	// RegisteredAt is when the plugin was first projected into the
	// in-process manager (replaces the HTTP registration timestamp).
	// +optional
	RegisteredAt *metav1.Time `json:"registeredAt,omitempty"`

	// Conditions track Ready / Registered / Healthy semantics.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration is the spec generation the controller last acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcpplug,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.serviceType`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.serviceURL`
// +kubebuilder:printcolumn:name="Healthy",type=boolean,JSONPath=`.status.healthy`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Plugin is the declarative form of POST /plugins/register: a third-party
// HTTP service the proxy fronts to extend its capabilities (smartagents
// runtimes, registry providers, virtualmcp gateways). The PluginReconciler
// (#19+) projects Plugin CRs into the in-process PluginServiceManager and
// keeps Status in sync with health-probe results.
type Plugin struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PluginSpec   `json:"spec,omitempty"`
	Status PluginStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PluginList contains a list of Plugin.
type PluginList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Plugin `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Plugin{}, &PluginList{})
}
