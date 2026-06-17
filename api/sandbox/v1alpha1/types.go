// Package v1alpha1 contains a minimal, local copy of the agent-sandbox
// Sandbox CRD types (sigs.k8s.io/agent-sandbox/api/v1alpha1). Only the
// fields the adapter reconciler needs are included; the full upstream
// module is not imported because it requires a controller-runtime version
// incompatible with this project.
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodMetadata carries labels and annotations for the managed pod.
type PodMetadata struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodTemplate wraps a PodSpec with optional metadata.
type PodTemplate struct {
	Spec     corev1.PodSpec `json:"spec"`
	Metadata PodMetadata    `json:"metadata"`
}

// SandboxSpec defines the desired state of a Sandbox.
type SandboxSpec struct {
	PodTemplate PodTemplate `json:"podTemplate"`
	// Service controls whether the agent-sandbox controller creates a
	// ClusterIP Service for this sandbox. Defaults to false.
	Service *bool `json:"service,omitempty"`
}

// SandboxStatus reflects the observed state of a Sandbox.
type SandboxStatus struct {
	ServiceFQDN string             `json:"serviceFQDN,omitempty"`
	Service     string             `json:"service,omitempty"`
	Conditions  []metav1.Condition `json:"conditions,omitempty"`
	PodIPs      []string           `json:"podIPs,omitempty"`
}

// Sandbox is a minimal mirror of the agent-sandbox Sandbox CRD
// (agents.x-k8s.io/v1alpha1). Only the subset of fields the adapter
// reconciler touches is defined.
type Sandbox struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SandboxSpec   `json:"spec,omitempty"`
	Status SandboxStatus `json:"status,omitempty"`
}

// SandboxList contains a list of Sandbox.
type SandboxList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Sandbox `json:"items"`
}
