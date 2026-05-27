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

// UserAuthProvider identifies the source-of-truth for a User's identity.
// Mirrors pkg/models.UserAuthProvider so the operator and HTTP-path code
// agree on provider names. "local" means the proxy-managed password store;
// external providers federate via OAuth/OIDC and the User CR records the
// linkage (ExternalID + ProviderGroups) rather than credentials.
// +kubebuilder:validation:Enum=local;github;rancher
type UserAuthProvider string

const (
	UserAuthProviderLocal   UserAuthProvider = "local"
	UserAuthProviderGitHub  UserAuthProvider = "github"
	UserAuthProviderRancher UserAuthProvider = "rancher"
)

// UserSpec declares a proxy-internal user. This is the proxy's auth model,
// complementary to native Kubernetes RBAC: cluster admins manage operator
// access via RBAC, while User/Group/RouteAssignment govern who can invoke
// MCP tools through the proxy data plane.
type UserSpec struct {
	// DisplayName is the human-readable name shown in UIs.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Email is the user's email address; used as the login identifier for
	// local-provider users and for display when federating.
	// +optional
	Email string `json:"email,omitempty"`

	// Groups names Group CRs (same namespace) this user belongs to. The
	// reverse edge lives in Group.Spec.Members; both are kept in sync by the
	// UserReconciler (denormalized to match the existing model). Membership
	// drives RouteAssignment matching at request time.
	// +optional
	Groups []corev1.LocalObjectReference `json:"groups,omitempty"`

	// AuthProvider selects which identity source backs this user. Defaults
	// to "local" if unset.
	// +optional
	AuthProvider UserAuthProvider `json:"authProvider,omitempty"`

	// ExternalID is the provider-side identifier (e.g. GitHub user id) used
	// to correlate federated logins back to this User. Ignored when
	// AuthProvider=local.
	// +optional
	ExternalID string `json:"externalID,omitempty"`

	// ProviderGroups are the raw group/team strings asserted by the external
	// provider (e.g. "myorg/sre"). The proxy maps these to Group CRs at
	// login time; surfaced here for auditing and debugging.
	// +optional
	ProviderGroups []string `json:"providerGroups,omitempty"`

	// PasswordSecretRef references a Secret holding the bcrypt password hash
	// for local-provider users. The key inside the Secret holds the hash;
	// the plaintext password is never stored in the CR. Ignored when
	// AuthProvider is anything other than "local".
	// +optional
	PasswordSecretRef *corev1.SecretKeySelector `json:"passwordSecretRef,omitempty"`
}

// UserPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Active;Disabled;Failed
type UserPhase string

const (
	UserPhasePending  UserPhase = "Pending"
	UserPhaseActive   UserPhase = "Active"
	UserPhaseDisabled UserPhase = "Disabled"
	UserPhaseFailed   UserPhase = "Failed"
)

// Condition types set by UserReconciler.
const (
	UserConditionReady          = "Ready"
	UserConditionGroupsResolved = "GroupsResolved"
)

// UserStatus reflects the observed state of a User.
type UserStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase UserPhase `json:"phase,omitempty"`

	// LastLoginTime is when the user last successfully authenticated.
	// +optional
	LastLoginTime *metav1.Time `json:"lastLoginTime,omitempty"`

	// PasswordChangedTime is when the local-provider password was last
	// rotated. Nil for non-local providers.
	// +optional
	PasswordChangedTime *metav1.Time `json:"passwordChangedTime,omitempty"`

	// Conditions track Ready / GroupsResolved semantics.
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
// +kubebuilder:resource:shortName=mcpuser,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.authProvider`
// +kubebuilder:printcolumn:name="Email",type=string,JSONPath=`.spec.email`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// User is a proxy-internal identity used by RouteAssignment to govern access
// to Adapters / VirtualMCPRoutes / Agents through the proxy data plane.
// Distinct from Kubernetes RBAC subjects, which govern operator access.
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec,omitempty"`
	Status UserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserList contains a list of User.
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}
