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

// RouteAssignmentPermission selects the level of access a RouteAssignment
// grants to the routes that reference it.
// +kubebuilder:validation:Enum=read;write;admin
type RouteAssignmentPermission string

const (
	RouteAssignmentPermissionRead  RouteAssignmentPermission = "read"
	RouteAssignmentPermissionWrite RouteAssignmentPermission = "write"
	RouteAssignmentPermissionAdmin RouteAssignmentPermission = "admin"
)

// RouteAssignmentSpec declares who may invoke the routes (Adapters,
// VirtualMCPRoutes, Agents) that reference this assignment. The
// target-references-assignment direction generalizes the old
// per-server-id model: a single RouteAssignment can be reused across many
// adapters/routes/agents instead of being scoped to one server.
type RouteAssignmentSpec struct {
	// Users names User CRs (same namespace) granted access by this
	// assignment.
	// +optional
	Users []corev1.LocalObjectReference `json:"users,omitempty"`

	// Groups names Group CRs (same namespace) granted access by this
	// assignment. A user matches if they appear in Users directly or via
	// any Group in this list.
	// +optional
	Groups []corev1.LocalObjectReference `json:"groups,omitempty"`

	// Permissions selects the access level granted to matched users.
	// Defaults to "read" when unset.
	// +optional
	Permissions RouteAssignmentPermission `json:"permissions,omitempty"`

	// AutoSpawn instructs the proxy to spawn the backing adapter/sidecar
	// on first matched request, rather than requiring it to be pre-warmed.
	// +optional
	AutoSpawn bool `json:"autoSpawn,omitempty"`

	// Description is a free-form summary surfaced in UIs.
	// +optional
	Description string `json:"description,omitempty"`

	// MCPServerRef, when set, makes this assignment server-scoped: the
	// proxy hot path will evaluate it for any Adapter whose
	// Spec.MCPServerRef matches, in addition to assignments referenced
	// explicitly via Adapter.Spec.RouteAssignmentRefs. Bridges the
	// legacy /api/v1/registry/{serverID}/routes HTTP surface onto the
	// CR-based model without mutating Adapter.Spec.
	// +optional
	MCPServerRef *corev1.LocalObjectReference `json:"mcpServerRef,omitempty"`
}

// RouteAssignmentPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Ready;Failed
type RouteAssignmentPhase string

const (
	RouteAssignmentPhasePending RouteAssignmentPhase = "Pending"
	RouteAssignmentPhaseReady   RouteAssignmentPhase = "Ready"
	RouteAssignmentPhaseFailed  RouteAssignmentPhase = "Failed"
)

// Condition types set by RouteAssignmentReconciler.
const (
	RouteAssignmentConditionReady             = "Ready"
	RouteAssignmentConditionSubjectsResolved  = "SubjectsResolved"
	RouteAssignmentConditionReferencedByRoute = "ReferencedByRoute"
)

// RouteAssignmentStatus reflects the observed state of a RouteAssignment.
type RouteAssignmentStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase RouteAssignmentPhase `json:"phase,omitempty"`

	// ResolvedSubjectCount is the total number of distinct users granted by
	// this assignment after expanding Groups.
	// +optional
	ResolvedSubjectCount int32 `json:"resolvedSubjectCount,omitempty"`

	// Conditions track Ready / SubjectsResolved / ReferencedByRoute
	// semantics.
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
// +kubebuilder:resource:shortName=racl,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Permissions",type=string,JSONPath=`.spec.permissions`
// +kubebuilder:printcolumn:name="Subjects",type=integer,JSONPath=`.status.resolvedSubjectCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RouteAssignment grants Users/Groups access to the Adapters,
// VirtualMCPRoutes, and Agents that reference this assignment via
// Spec.RouteAssignmentRefs / Spec.ACL. The proxy evaluates assignments at
// request time and rejects calls from unmatched subjects.
type RouteAssignment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RouteAssignmentSpec   `json:"spec,omitempty"`
	Status RouteAssignmentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RouteAssignmentList contains a list of RouteAssignment.
type RouteAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RouteAssignment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RouteAssignment{}, &RouteAssignmentList{})
}
