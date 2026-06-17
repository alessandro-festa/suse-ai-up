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

// MCPRegistrySource declares where a registry pulls its MCPServer entries
// from. Exactly one of the three sub-fields must be set; enforcement is the
// reconciler's responsibility (CEL validation can be added later).
type MCPRegistrySource struct {
	// URL is a remote registry YAML endpoint (HTTP or HTTPS).
	// +optional
	URL string `json:"url,omitempty"`

	// ConfigMapRef references a ConfigMap (same namespace) containing the
	// registry YAML in a single key. Useful for GitOps flows.
	// +optional
	ConfigMapRef *corev1.LocalObjectReference `json:"configMapRef,omitempty"`

	// Inline is an embedded list of MCPServer entries. Useful for small or
	// project-local registries with no external source.
	// +optional
	Inline []MCPServerSpec `json:"inline,omitempty"`
}

// MCPRegistrySpec defines the desired state of an MCPRegistry — one source
// of MCPServer entries. Multiple registries can coexist; Priority resolves
// name conflicts across them.
type MCPRegistrySpec struct {
	// Source is where this registry's entries come from.
	Source MCPRegistrySource `json:"source"`

	// Format identifies the payload format of the registry source.
	// Defaults to "" which is treated as "yaml" (the legacy list-of-maps
	// format). Use "mcp-registry-v0.1" for the official MCP registry JSON
	// format at registry.modelcontextprotocol.io.
	// +kubebuilder:validation:Enum="";"yaml";"mcp-registry-v0.1"
	// +optional
	Format string `json:"format,omitempty"`

	// RefreshInterval controls how often the controller re-syncs from
	// Source. Defaults to 5m when unset. Ignored for inline sources (no
	// external state to poll).
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`

	// Priority resolves name conflicts when two registries provide an
	// MCPServer with the same name. Higher priority wins; ties are broken
	// by creation timestamp (older wins). Negative values are allowed.
	// +optional
	Priority int32 `json:"priority,omitempty"`
}

// MCPRegistryPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Syncing;Ready;Failed
type MCPRegistryPhase string

const (
	MCPRegistryPhasePending MCPRegistryPhase = "Pending"
	MCPRegistryPhaseSyncing MCPRegistryPhase = "Syncing"
	MCPRegistryPhaseReady   MCPRegistryPhase = "Ready"
	MCPRegistryPhaseFailed  MCPRegistryPhase = "Failed"
)

// Condition types set by MCPRegistryReconciler.
const (
	MCPRegistryConditionReady  = "Ready"
	MCPRegistryConditionSynced = "Synced"
)

// MCPRegistryStatus reflects the observed state of an MCPRegistry.
type MCPRegistryStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase MCPRegistryPhase `json:"phase,omitempty"`

	// LastSyncTime is when the controller last successfully reconciled
	// Source into child MCPServer entries.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedServerCount is the number of MCPServer entries currently
	// owned by this registry.
	// +optional
	ObservedServerCount int32 `json:"observedServerCount,omitempty"`

	// SyncError carries the most recent fetch/parse error, if any. Cleared
	// once a sync succeeds.
	// +optional
	SyncError string `json:"syncError,omitempty"`

	// Conditions track Ready / Synced semantics.
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
// +kubebuilder:resource:shortName=mcpreg,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Servers",type=integer,JSONPath=`.status.observedServerCount`
// +kubebuilder:printcolumn:name="LastSync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MCPRegistry is one source of MCPServer entries. Multiple registries
// coexist; Spec.Priority resolves name conflicts across them. The
// MCPRegistryReconciler (#17) creates child MCPServer CRs with
// OwnerReference set to this registry so deletion cascades automatically.
type MCPRegistry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPRegistrySpec   `json:"spec,omitempty"`
	Status MCPRegistryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPRegistryList contains a list of MCPRegistry.
type MCPRegistryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPRegistry `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPRegistry{}, &MCPRegistryList{})
}
