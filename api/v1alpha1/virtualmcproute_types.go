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

// VirtualMCPSelector picks tools or resources out of a source's catalog.
// Exactly one of All / Names / Prefix / Regex should be set; the reconciler
// enforces this (CEL validation can be added later).
type VirtualMCPSelector struct {
	// All matches every entry in the source's catalog.
	// +optional
	All bool `json:"all,omitempty"`

	// Names is an explicit allow-list of entry names.
	// +optional
	Names []string `json:"names,omitempty"`

	// Prefix matches any entry whose name starts with this string.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Regex matches any entry whose name matches this Go regexp.
	// +optional
	Regex string `json:"regex,omitempty"`
}

// VirtualMCPSourceRewrite renames or namespaces tools/resources from a
// source when the route flattens its catalog.
type VirtualMCPSourceRewrite struct {
	// Prefix prepended to every selected name.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Suffix appended to every selected name.
	// +optional
	Suffix string `json:"suffix,omitempty"`
}

// VirtualMCPSource is one Adapter or MCPServer contributing entries to the
// virtual route. Exactly one of AdapterRef / MCPServerRef must be set.
type VirtualMCPSource struct {
	// AdapterRef references an Adapter CR (same namespace) to draw entries
	// from.
	// +optional
	AdapterRef *corev1.LocalObjectReference `json:"adapterRef,omitempty"`

	// MCPServerRef references an MCPServer CR (same namespace) to draw
	// entries from.
	// +optional
	MCPServerRef *corev1.LocalObjectReference `json:"mcpServerRef,omitempty"`

	// Tools selects which tools to include. Defaults to none if unset (use
	// {all: true} to include them all).
	// +optional
	Tools *VirtualMCPSelector `json:"tools,omitempty"`

	// Resources selects which resources to include.
	// +optional
	Resources *VirtualMCPSelector `json:"resources,omitempty"`

	// Prompts selects which prompts to include.
	// +optional
	Prompts *VirtualMCPSelector `json:"prompts,omitempty"`

	// Rewrite renames selected entries with a prefix/suffix to avoid
	// collisions with entries from other sources.
	// +optional
	Rewrite *VirtualMCPSourceRewrite `json:"rewrite,omitempty"`
}

// VirtualMCPRouteSpec defines the desired state of a VirtualMCPRoute — a
// composed MCP endpoint built from selected tools/resources of one or more
// Adapters / MCPServers. Served at /api/v1/vroutes/{exposedAs}/mcp by the
// proxy.
type VirtualMCPRouteSpec struct {
	// ExposedAs is the path segment under /api/v1/vroutes/ where this route
	// is served. Defaults to metadata.name when unset.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ExposedAs string `json:"exposedAs,omitempty"`

	// Description is a human-readable summary shown in UIs.
	// +optional
	Description string `json:"description,omitempty"`

	// Sources are the Adapter / MCPServer references contributing entries
	// to this route.
	// +kubebuilder:validation:MinItems=1
	Sources []VirtualMCPSource `json:"sources"`

	// ACL names RouteAssignment CRs governing who can invoke this route.
	// Empty means no per-route ACL is enforced (the cluster-wide default
	// still applies).
	// +optional
	ACL []corev1.LocalObjectReference `json:"acl,omitempty"`
}

// ResolvedEntryKind identifies what kind of MCP entry was resolved.
// +kubebuilder:validation:Enum=tool;resource;prompt
type ResolvedEntryKind string

const (
	ResolvedEntryKindTool     ResolvedEntryKind = "tool"
	ResolvedEntryKindResource ResolvedEntryKind = "resource"
	ResolvedEntryKindPrompt   ResolvedEntryKind = "prompt"
)

// ResolvedEntry is one tool / resource / prompt flattened into the route's
// catalog after selectors and rewrites are applied.
type ResolvedEntry struct {
	// Name is the externally exposed name (after rewrite).
	Name string `json:"name"`

	// Kind tells clients which MCP catalog this entry belongs to.
	Kind ResolvedEntryKind `json:"kind"`

	// OriginalName is the entry's name on its source (pre-rewrite); empty
	// when no rewrite was applied.
	// +optional
	OriginalName string `json:"originalName,omitempty"`

	// SourceAdapter is the Adapter CR name the entry came from, if any.
	// +optional
	SourceAdapter string `json:"sourceAdapter,omitempty"`

	// SourceMCPServer is the MCPServer CR name the entry came from, if any.
	// +optional
	SourceMCPServer string `json:"sourceMCPServer,omitempty"`
}

// VirtualMCPRoutePhase is the high-level rollup of Status.Conditions.
// +kubebuilder:validation:Enum=Pending;Resolving;Ready;Degraded;Failed
type VirtualMCPRoutePhase string

const (
	VirtualMCPRoutePhasePending   VirtualMCPRoutePhase = "Pending"
	VirtualMCPRoutePhaseResolving VirtualMCPRoutePhase = "Resolving"
	VirtualMCPRoutePhaseReady     VirtualMCPRoutePhase = "Ready"
	VirtualMCPRoutePhaseDegraded  VirtualMCPRoutePhase = "Degraded"
	VirtualMCPRoutePhaseFailed    VirtualMCPRoutePhase = "Failed"
)

// Condition types set by VirtualMCPRouteReconciler.
const (
	VirtualMCPRouteConditionReady         = "Ready"
	VirtualMCPRouteConditionSourceMissing = "SourceMissing"
	VirtualMCPRouteConditionConflict      = "Conflict"
)

// VirtualMCPRouteStatus reflects the observed state of a VirtualMCPRoute.
type VirtualMCPRouteStatus struct {
	// Phase is the high-level rollup of Conditions.
	// +optional
	Phase VirtualMCPRoutePhase `json:"phase,omitempty"`

	// EndpointURL is the proxy-fronted MCP URL clients use to reach this
	// route (e.g. http://proxy/api/v1/vroutes/<exposedAs>/mcp).
	// +optional
	EndpointURL string `json:"endpointURL,omitempty"`

	// ResolvedEntries is the flattened catalog with origin metadata. Large
	// routes can produce large status payloads — UIs that need only a count
	// should read Status.EntryCount instead.
	// +optional
	// +listType=atomic
	ResolvedEntries []ResolvedEntry `json:"resolvedEntries,omitempty"`

	// EntryCount is the size of ResolvedEntries; surfaced as its own field
	// so it can be a printer column without paging through the full list.
	// +optional
	EntryCount int32 `json:"entryCount,omitempty"`

	// Conditions track Ready / SourceMissing / Conflict semantics.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// LastResolvedTime is when the controller last successfully resolved
	// the catalog.
	// +optional
	LastResolvedTime *metav1.Time `json:"lastResolvedTime,omitempty"`

	// ObservedGeneration is the spec generation the controller last acted on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vroute,categories={suse-ai,mcp}
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="ExposedAs",type=string,JSONPath=`.spec.exposedAs`
// +kubebuilder:printcolumn:name="Entries",type=integer,JSONPath=`.status.entryCount`
// +kubebuilder:printcolumn:name="LastResolved",type=date,JSONPath=`.status.lastResolvedTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VirtualMCPRoute composes a new MCP endpoint out of selected tools,
// resources, and prompts from one or more Adapters / MCPServers. The
// VirtualMCPRouteReconciler (#17) resolves the flattened catalog and
// publishes it into the proxy's in-process routing table — no Kubernetes
// workload is created for a route.
type VirtualMCPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualMCPRouteSpec   `json:"spec,omitempty"`
	Status VirtualMCPRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VirtualMCPRouteList contains a list of VirtualMCPRoute.
type VirtualMCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualMCPRoute `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualMCPRoute{}, &VirtualMCPRouteList{})
}
