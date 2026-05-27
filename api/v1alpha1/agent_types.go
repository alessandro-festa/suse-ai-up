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

// AgentToolRef is one tool reference the agent is allowed to invoke. Exactly
// one of AdapterRef / VirtualMCPRouteRef must be set. The proxy enforces
// the ACL at request time, so anything the agent calls outside this list is
// rejected even if the underlying adapter is otherwise reachable.
type AgentToolRef struct {
	// AdapterRef references an Adapter CR (same namespace).
	// +optional
	AdapterRef *corev1.LocalObjectReference `json:"adapterRef,omitempty"`

	// VirtualMCPRouteRef references a VirtualMCPRoute CR (same namespace).
	// +optional
	VirtualMCPRouteRef *corev1.LocalObjectReference `json:"virtualMCPRouteRef,omitempty"`
}

// AgentRuntime is the optional external-runtime spec. When set the
// AgentReconciler (#17) creates an owned Deployment+Service for the agent;
// when nil the agent is served in-process by the proxy translating its
// protocol to MCP calls.
type AgentRuntime struct {
	// Image is the container image for the agent runtime.
	Image string `json:"image"`

	// Args overrides the image's default command arguments.
	// +optional
	Args []string `json:"args,omitempty"`

	// Env are environment variables passed to the runtime. Supports
	// SecretKeySelector / ConfigMapKeySelector via ValueFrom.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Port the runtime listens on.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Resources are the container resource requests/limits.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Replicas is the desired runtime replica count. Defaults to 1.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitempty"`
}

// AgentSpec declares an agent served on top of MCP. The protocol selects
// which registered AgentProtocol implementation (in pkg/services/agents/)
// translates between the agent surface and the underlying tool calls.
type AgentSpec struct {
	// Protocol identifies the AgentProtocol implementation that serves this
	// agent (e.g. "a2a", "smartagents"). Free-form string so new protocols
	// can be added without CRD churn; the proxy fails the agent
	// (Status.Phase=Failed, Condition ProtocolUnknown=True) if no
	// implementation is registered.
	// +kubebuilder:validation:MinLength=1
	Protocol string `json:"protocol"`

	// Description is a human-readable summary shown in UIs.
	// +optional
	Description string `json:"description,omitempty"`

	// Tools lists the Adapters / VirtualMCPRoutes the agent is allowed to
	// call. Acts as a hard ACL enforced by the proxy at request time. Empty
	// means the agent has no tool access (it can still respond to protocol
	// calls that don't require a tool).
	// +optional
	Tools []AgentToolRef `json:"tools,omitempty"`

	// Runtime, when set, causes the controller to deploy an external
	// agent-runtime Deployment+Service. When nil the agent is served
	// in-process by the proxy translating the protocol to MCP calls.
	// +optional
	Runtime *AgentRuntime `json:"runtime,omitempty"`

	// ACL names RouteAssignment CRs governing who can invoke this agent.
	// +optional
	ACL []corev1.LocalObjectReference `json:"acl,omitempty"`
}

// AgentMode reflects whether the agent is served in-process by the proxy
// or by an external runtime Deployment.
// +kubebuilder:validation:Enum=InProcess;External
type AgentMode string

const (
	AgentModeInProcess AgentMode = "InProcess"
	AgentModeExternal  AgentMode = "External"
)

// AgentPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Registered;Provisioning;Ready;Degraded;Failed
type AgentPhase string

const (
	AgentPhasePending      AgentPhase = "Pending"
	AgentPhaseRegistered   AgentPhase = "Registered"
	AgentPhaseProvisioning AgentPhase = "Provisioning"
	AgentPhaseReady        AgentPhase = "Ready"
	AgentPhaseDegraded     AgentPhase = "Degraded"
	AgentPhaseFailed       AgentPhase = "Failed"
)

// Condition types set by AgentReconciler.
const (
	AgentConditionReady           = "Ready"
	AgentConditionProtocolUnknown = "ProtocolUnknown"
	AgentConditionToolMissing     = "ToolMissing"
)

// AgentStatus reflects the observed state of an Agent.
type AgentStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase AgentPhase `json:"phase,omitempty"`

	// Mode tells callers whether the agent runs in-process inside the proxy
	// or as a separate Deployment.
	// +optional
	Mode AgentMode `json:"mode,omitempty"`

	// EndpointURL is where clients reach the agent (e.g.
	// http://proxy/api/v1/agents/<name>/...).
	// +optional
	EndpointURL string `json:"endpointURL,omitempty"`

	// RuntimeDeploymentRef points at the Deployment AgentReconciler owns
	// when Mode=External.
	// +optional
	RuntimeDeploymentRef *corev1.LocalObjectReference `json:"runtimeDeploymentRef,omitempty"`

	// Conditions track Ready / ProtocolUnknown / ToolMissing semantics.
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
// +kubebuilder:resource:shortName=agent,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Protocol",type=string,JSONPath=`.spec.protocol`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.status.mode`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpointURL`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Agent declares an agent served on top of MCP, supporting multiple agent
// protocols (A2A and future). The AgentReconciler (#17) registers the
// agent with the proxy in-process or, when Spec.Runtime is set, owns an
// external runtime Deployment+Service.
type Agent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentSpec   `json:"spec,omitempty"`
	Status AgentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AgentList contains a list of Agent.
type AgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Agent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Agent{}, &AgentList{})
}
