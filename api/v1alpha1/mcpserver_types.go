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

// MCPServerRepository captures the upstream source of an MCP server's code.
type MCPServerRepository struct {
	// URL is the repository URL.
	URL string `json:"url"`

	// Source identifies the hosting service (github, gitlab, etc.).
	// +optional
	Source string `json:"source,omitempty"`
}

// MCPServerTransport describes how to connect to an MCP server package.
type MCPServerTransport struct {
	// Type is the transport identifier (stdio, sse, websocket, http).
	// +kubebuilder:validation:Enum=stdio;sse;websocket;http
	Type string `json:"type"`
}

// MCPServerEnvVar describes a runtime environment variable the server
// expects. It is purely declarative — the Adapter that consumes this
// MCPServer is responsible for satisfying secret values.
type MCPServerEnvVar struct {
	// Name is the environment variable name.
	Name string `json:"name"`

	// Description is a short human-readable note about the variable.
	// +optional
	Description string `json:"description,omitempty"`

	// Format is a hint about the expected value shape (string, number,
	// boolean).
	// +kubebuilder:validation:Enum=string;number;boolean
	// +optional
	Format string `json:"format,omitempty"`

	// IsSecret marks the variable as sensitive so UIs render it accordingly
	// and Adapter authors know to supply it via Secret rather than inline.
	// +optional
	IsSecret bool `json:"isSecret,omitempty"`

	// Default is the value used when no Adapter override is supplied.
	// +optional
	Default string `json:"default,omitempty"`
}

// MCPServerPackage describes one shipped artifact (OCI image, npm package,
// etc.) that runs the MCP server.
type MCPServerPackage struct {
	// RegistryType identifies the package registry (oci, npm, pypi, etc.).
	RegistryType string `json:"registryType"`

	// Identifier is the package identifier inside RegistryType (e.g.
	// `docker.io/user/image:tag`).
	Identifier string `json:"identifier"`

	// Transport is how the proxy speaks to this package once running.
	Transport MCPServerTransport `json:"transport"`

	// EnvironmentVariables documents the env vars the package recognizes.
	// +optional
	EnvironmentVariables []MCPServerEnvVar `json:"environmentVariables,omitempty"`
}

// MCPServerSpec is the declarative form of an MCP server entry. The same
// shape is used both as a standalone CR's Spec and as an entry inside
// MCPRegistrySpec.Source.Inline.
type MCPServerSpec struct {
	// DisplayName is the human-readable name shown in UIs.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Description is a short summary of what this server provides.
	// +optional
	Description string `json:"description,omitempty"`

	// Version is the upstream version this entry describes.
	// +optional
	Version string `json:"version,omitempty"`

	// Image is the primary container image for containerized servers.
	// +optional
	Image string `json:"image,omitempty"`

	// Port is the network port the server listens on.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// URL is the endpoint for remote-hosted MCP servers.
	// +optional
	URL string `json:"url,omitempty"`

	// Repository describes where the server source lives.
	// +optional
	Repository *MCPServerRepository `json:"repository,omitempty"`

	// Packages are the shipped artifacts (OCI image, npm package, etc.).
	// +optional
	Packages []MCPServerPackage `json:"packages,omitempty"`

	// Categories group servers by domain (e.g. "monitoring", "ci").
	// +optional
	Categories []string `json:"categories,omitempty"`

	// Tags are free-form labels used for search/filter.
	// +optional
	Tags []string `json:"tags,omitempty"`
}

// MCPServerPhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Active;Conflict;Inactive
type MCPServerPhase string

const (
	MCPServerPhasePending  MCPServerPhase = "Pending"
	MCPServerPhaseActive   MCPServerPhase = "Active"
	MCPServerPhaseConflict MCPServerPhase = "Conflict"
	MCPServerPhaseInactive MCPServerPhase = "Inactive"
)

// Condition types set by MCPServerReconciler.
const (
	MCPServerConditionReady    = "Ready"
	MCPServerConditionConflict = "Conflict"
)

// MCPServerStatus reflects the observed state of an MCPServer.
type MCPServerStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase MCPServerPhase `json:"phase,omitempty"`

	// SourceRegistry is the name of the MCPRegistry that owns this entry.
	// Set automatically by MCPRegistryReconciler via OwnerReference; surfaced
	// here for convenient querying.
	// +optional
	SourceRegistry string `json:"sourceRegistry,omitempty"`

	// Priority is copied from the originating MCPRegistry.Spec.Priority and
	// used by other registries' reconcilers to detect/resolve name conflicts.
	// +optional
	Priority int32 `json:"priority,omitempty"`

	// Conditions track Ready / Conflict semantics.
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
// +kubebuilder:resource:shortName=mcpsrv,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.status.sourceRegistry`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.status.priority`
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MCPServer is one entry per MCP server definition. Typically created by an
// MCPRegistry controller (via OwnerReference) from a source registry; can
// also be created standalone for one-off declarative entries.
type MCPServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPServerSpec   `json:"spec,omitempty"`
	Status MCPServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPServerList contains a list of MCPServer.
type MCPServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MCPServer{}, &MCPServerList{})
}
