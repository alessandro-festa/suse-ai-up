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

// GroupSpec declares a proxy-internal group: a named bundle of Users plus a
// permission set. Groups are the primary unit RouteAssignment refers to;
// granting a group access to a route implicitly grants every member.
type GroupSpec struct {
	// DisplayName is the human-readable name shown in UIs.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Description is a free-form summary surfaced in UIs.
	// +optional
	Description string `json:"description,omitempty"`

	// Members names User CRs (same namespace) that belong to this group.
	// Denormalized with User.Spec.Groups; the GroupReconciler keeps both
	// edges in sync (matches the existing model where membership is stored
	// on both sides).
	// +optional
	Members []corev1.LocalObjectReference `json:"members,omitempty"`

	// Permissions are coarse-grained permission strings (e.g.
	// "server:read", "adapter:create") evaluated by the proxy at request
	// time. Free-form to avoid CRD churn as new permission verbs are added.
	// +optional
	Permissions []string `json:"permissions,omitempty"`
}

// GroupPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Ready;Failed
type GroupPhase string

const (
	GroupPhasePending GroupPhase = "Pending"
	GroupPhaseReady   GroupPhase = "Ready"
	GroupPhaseFailed  GroupPhase = "Failed"
)

// Condition types set by GroupReconciler.
const (
	GroupConditionReady           = "Ready"
	GroupConditionMembersResolved = "MembersResolved"
)

// GroupStatus reflects the observed state of a Group.
type GroupStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase GroupPhase `json:"phase,omitempty"`

	// MemberCount is the number of resolved User CRs in Spec.Members.
	// +optional
	MemberCount int32 `json:"memberCount,omitempty"`

	// Conditions track Ready / MembersResolved semantics.
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
// +kubebuilder:resource:shortName=mcpgroup,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Members",type=integer,JSONPath=`.status.memberCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Group is a named bundle of Users plus a permission set, referenced by
// RouteAssignment to grant access to Adapters / VirtualMCPRoutes / Agents.
// Distinct from Kubernetes RBAC groups, which govern operator access.
type Group struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GroupSpec   `json:"spec,omitempty"`
	Status GroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GroupList contains a list of Group.
type GroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Group `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Group{}, &GroupList{})
}
