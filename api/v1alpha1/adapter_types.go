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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectionType identifies how the proxy speaks to the upstream MCP server
// behind an Adapter. Mirrors pkg/models ConnectionType so the operator and the
// existing HTTP-path code agree on transport identifiers.
// +kubebuilder:validation:Enum=LocalStdio;StreamableHttp;RemoteHttp;SSE;SidecarStdio
type ConnectionType string

const (
	ConnectionTypeLocalStdio     ConnectionType = "LocalStdio"
	ConnectionTypeStreamableHTTP ConnectionType = "StreamableHttp"
	ConnectionTypeRemoteHTTP     ConnectionType = "RemoteHttp"
	ConnectionTypeSSE            ConnectionType = "SSE"
	ConnectionTypeSidecarStdio   ConnectionType = "SidecarStdio"
)

// AdapterAuthType selects which AdapterAuthentication sub-struct applies.
// +kubebuilder:validation:Enum=none;bearer;oauth;basic;apikey
type AdapterAuthType string

const (
	AdapterAuthTypeNone   AdapterAuthType = "none"
	AdapterAuthTypeBearer AdapterAuthType = "bearer"
	AdapterAuthTypeOAuth  AdapterAuthType = "oauth"
	AdapterAuthTypeBasic  AdapterAuthType = "basic"
	AdapterAuthTypeAPIKey AdapterAuthType = "apikey"
)

// AdapterSource declares where the upstream MCP server comes from. Exactly
// one of MCPServerRef or SidecarConfig must be set; this is enforced at the
// reconciler boundary (CEL validation arrives with the controller in #17).
type AdapterSource struct {
	// MCPServerRef references an MCPServer CR (same namespace) that provides
	// the sidecar template. Use this when the server entry already lives in a
	// registered MCPRegistry.
	// +optional
	MCPServerRef *corev1.LocalObjectReference `json:"mcpServerRef,omitempty"`

	// SidecarConfig is an inline alternative to MCPServerRef for one-off
	// adapters that aren't backed by a registry entry.
	// +optional
	SidecarConfig *SidecarConfig `json:"sidecarConfig,omitempty"`

	// RemoteURL is the upstream URL for RemoteHttp / SSE connection types.
	// Ignored for stdio/sidecar variants.
	// +optional
	RemoteURL string `json:"remoteURL,omitempty"`
}

// SidecarConfig is the inline form of an adapter's runtime spec; mirrors
// pkg/models.SidecarConfig but uses typed env vars and an int32 port.
type SidecarConfig struct {
	// CommandType identifies the launcher family (docker, npx, python, pip).
	// +kubebuilder:validation:Enum=docker;npx;python;pip
	CommandType string `json:"commandType"`

	// Command is the entrypoint binary inside the sidecar.
	Command string `json:"command"`

	// Args are the arguments passed to Command.
	// +optional
	Args []string `json:"args,omitempty"`

	// Image is the container image when CommandType=docker.
	// +optional
	Image string `json:"image,omitempty"`

	// Env are environment variables exposed to the sidecar. Supports
	// SecretKeySelector / ConfigMapKeySelector via ValueFrom so secrets stay
	// out of the CR.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Port the sidecar listens on; defaults to a controller-assigned port if
	// unset.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Source records the origin of the config (e.g. registry name, manual).
	// +optional
	Source string `json:"source,omitempty"`

	// ProjectURL points at the upstream MCP server source.
	// +optional
	ProjectURL string `json:"projectURL,omitempty"`

	// ReleaseURL points at the specific release used.
	// +optional
	ReleaseURL string `json:"releaseURL,omitempty"`
}

// AdapterAuthentication declares how clients authenticate when proxying
// through this adapter. Secret material is referenced, never inlined.
type AdapterAuthentication struct {
	// Required indicates whether unauthenticated callers are rejected.
	Required bool `json:"required"`

	// Type selects which sub-struct below applies.
	Type AdapterAuthType `json:"type"`

	// +optional
	BearerToken *BearerTokenAuth `json:"bearerToken,omitempty"`
	// +optional
	OAuth *OAuthAuth `json:"oauth,omitempty"`
	// +optional
	Basic *BasicAuth `json:"basic,omitempty"`
	// +optional
	APIKey *APIKeyAuth `json:"apiKey,omitempty"`
}

// BearerTokenAuth references a static bearer token in a Secret, or marks the
// adapter as using the proxy's dynamic token manager.
type BearerTokenAuth struct {
	// SecretRef is the secret + key holding the static bearer token.
	// +optional
	SecretRef *corev1.SecretKeySelector `json:"secretRef,omitempty"`

	// Dynamic switches the proxy to its built-in token manager and ignores
	// SecretRef.
	// +optional
	Dynamic bool `json:"dynamic,omitempty"`
}

// OAuthAuth declares the OAuth client configuration. Client secret is
// referenced from a Secret.
type OAuthAuth struct {
	// +optional
	ClientID string `json:"clientId,omitempty"`
	// +optional
	ClientSecretRef *corev1.SecretKeySelector `json:"clientSecretRef,omitempty"`
	// +optional
	AuthURL string `json:"authURL,omitempty"`
	// +optional
	TokenURL string `json:"tokenURL,omitempty"`
	// +optional
	Scopes []string `json:"scopes,omitempty"`
	// +optional
	RedirectURI string `json:"redirectURI,omitempty"`
}

// BasicAuth references HTTP Basic credentials in a Secret.
type BasicAuth struct {
	// SecretRef holds keys "username" and "password" in the referenced Secret.
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// APIKeyAuth describes an API key sent in a header, query parameter, or cookie.
type APIKeyAuth struct {
	// KeySecretRef is the secret + key containing the API key value.
	KeySecretRef corev1.SecretKeySelector `json:"keySecretRef"`

	// Location is where the key is placed on outbound requests.
	// +kubebuilder:validation:Enum=header;query;cookie
	Location string `json:"location"`

	// Name is the header / query parameter / cookie name carrying the key.
	Name string `json:"name"`
}

// AdapterSpec defines the desired state of an Adapter — a proxy-fronted MCP
// server endpoint reachable at /api/v1/adapters/{name}/mcp.
type AdapterSpec struct {
	// Source declares where the upstream MCP server comes from.
	Source AdapterSource `json:"source"`

	// ConnectionType selects the transport the proxy uses to reach the
	// upstream.
	ConnectionType ConnectionType `json:"connectionType"`

	// Authentication describes how callers authenticate when invoking this
	// adapter through the proxy. Absent means no auth is enforced.
	// +optional
	Authentication *AdapterAuthentication `json:"authentication,omitempty"`

	// RouteAssignmentRefs name RouteAssignment CRs that grant
	// user/group access to this adapter. Empty means no ACL is enforced
	// (the cluster-wide default still applies).
	// +optional
	RouteAssignmentRefs []corev1.LocalObjectReference `json:"routeAssignmentRefs,omitempty"`

	// Variables are name/value pairs substituted into the sidecar config at
	// reconcile time (the `{{var.name}}` template form used by the existing
	// adapter service).
	// +optional
	Variables map[string]string `json:"variables,omitempty"`

	// Replicas is the desired number of sidecar pods. Defaults to 1.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitempty"`

	// Description is a human-readable summary surfaced in UIs.
	// +optional
	Description string `json:"description,omitempty"`
}

// AdapterPhase is the high-level rollup of Status.Conditions; kept here so
// `kubectl get adapters` is useful without -o yaml.
// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Degraded;Failed;Terminating
type AdapterPhase string

const (
	AdapterPhasePending      AdapterPhase = "Pending"
	AdapterPhaseProvisioning AdapterPhase = "Provisioning"
	AdapterPhaseReady        AdapterPhase = "Ready"
	AdapterPhaseDegraded     AdapterPhase = "Degraded"
	AdapterPhaseFailed       AdapterPhase = "Failed"
	AdapterPhaseTerminating  AdapterPhase = "Terminating"
)

// Condition types set by AdapterReconciler.
const (
	AdapterConditionReady   = "Ready"
	AdapterConditionSynced  = "Synced"
	AdapterConditionHealthy = "Healthy"
)

// AdapterStatus reflects the observed state of an Adapter.
type AdapterStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase AdapterPhase `json:"phase,omitempty"`

	// EndpointURL is the proxy-fronted MCP URL clients use to reach this
	// adapter.
	// +optional
	EndpointURL string `json:"endpointURL,omitempty"`

	// SidecarDeploymentRef points at the Deployment AdapterReconciler owns
	// for this adapter, when one exists (stdio/sidecar transports).
	// +optional
	SidecarDeploymentRef *corev1.LocalObjectReference `json:"sidecarDeploymentRef,omitempty"`

	// Conditions track Ready / Synced / Healthy semantics.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// LastCapabilitySnapshotTime is when the proxy last cached the upstream
	// MCP capabilities for this adapter.
	// +optional
	LastCapabilitySnapshotTime *metav1.Time `json:"lastCapabilitySnapshotTime,omitempty"`

	// ObservedGeneration is the spec generation the controller last acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mcpa,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Connection",type=string,JSONPath=`.spec.connectionType`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpointURL`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Adapter is the proxy-fronted MCP server endpoint reachable at
// /api/v1/adapters/{name}/mcp. The AdapterReconciler (#17) materializes the
// backing Deployment+Service when the connection type requires one.
type Adapter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdapterSpec   `json:"spec,omitempty"`
	Status AdapterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AdapterList contains a list of Adapter.
type AdapterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Adapter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Adapter{}, &AdapterList{})
}
