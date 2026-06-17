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

package controllers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	sandboxv1alpha1 "github.com/SUSE/suse-ai-up/api/sandbox/v1alpha1"
	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// ErrUnsupportedCommandType is returned by BuildDeployment when the adapter
// declares a sidecar CommandType the builder does not yet know how to render.
// Only "docker" is supported in this iteration; npx/python/pip will follow
// in a separate PR once their fixtures and CRD shape are settled.
var ErrUnsupportedCommandType = errors.New("adapter sidecar commandType not supported by builder")

// ErrMissingSidecarConfig is returned when the adapter's ConnectionType
// implies a sidecar workload but Spec.Source.SidecarConfig is nil.
var ErrMissingSidecarConfig = errors.New("adapter requires a sidecar but Spec.Source.SidecarConfig is nil")

const (
	// defaultSidecarPort matches the legacy default in
	// pkg/proxy/sidecar_manager.go so existing adapter examples keep working
	// after migration to the CRD path.
	defaultSidecarPort int32 = 3000

	// commonNameLabel / managedComponent are the standard
	// app.kubernetes.io/* labels applied to every Deployment+Service the
	// reconciler owns.
	commonNameLabel  = "suse-ai-up"
	managedComponent = "adapter-sidecar"

	// adapterLabelKey carries the owning Adapter CR name and is the primary
	// selector label so Deployment <-> Service stay paired even if other
	// labels shift over time.
	adapterLabelKey = "mcp.suse.com/adapter"

	// DefaultMCPProxyImage is the sidecar image used for Sandbox-backed
	// adapters. It bundles mcp-proxy (Mode 2 — server-side) with Python/uv
	// and Node.js runtimes so it can spawn any STDIO-based MCP server and
	// expose it as streamable-HTTP.
	DefaultMCPProxyImage = "suse-ai-up-mcp-proxy:latest"
)

// connectionTypeNeedsSidecar reports whether the proxy must materialize a
// Deployment+Service for the given connection type. Remote / pure-HTTP
// connections are handled by the proxy talking directly to the upstream,
// so no workload is owned by the reconciler.
func connectionTypeNeedsSidecar(ct mcpv1alpha1.ConnectionType) bool {
	switch ct {
	case mcpv1alpha1.ConnectionTypeLocalStdio,
		mcpv1alpha1.ConnectionTypeSidecarStdio,
		mcpv1alpha1.ConnectionTypeStreamableHTTP:
		return true
	default:
		return false
	}
}

// sidecarObjectName is the deterministic name shared by the Deployment and
// the Service backing an Adapter. Prefixing keeps the workload-namespace
// flat-listable and prevents accidental collisions with unrelated objects.
func sidecarObjectName(adapter *mcpv1alpha1.Adapter) string {
	return "adapter-" + adapter.Name
}

// sidecarLabels returns the label set applied to both the Deployment's pod
// template and the Service selector. The adapter-name label is what binds
// the two together; the rest are informational.
func sidecarLabels(adapter *mcpv1alpha1.Adapter) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      commonNameLabel,
		"app.kubernetes.io/component": managedComponent,
		adapterLabelKey:               adapter.Name,
	}
}

// sidecarSelector is the subset of labels used as the pod selector. Pod
// selectors are immutable, so keep this minimal and stable across releases.
func sidecarSelector(adapter *mcpv1alpha1.Adapter) map[string]string {
	return map[string]string{
		"app.kubernetes.io/component": managedComponent,
		adapterLabelKey:               adapter.Name,
	}
}

// BuildDeployment renders the *appsv1.Deployment for an Adapter whose
// ConnectionType requires a sidecar. The function is pure — no client, no
// I/O — so it is exhaustively unit-testable. Caller is responsible for
// setting OwnerReferences and applying the object.
func BuildDeployment(adapter *mcpv1alpha1.Adapter, workloadNamespace string, variables map[string]string) (*appsv1.Deployment, error) {
	if adapter.Spec.Source.SidecarConfig == nil {
		return nil, ErrMissingSidecarConfig
	}
	cfg := adapter.Spec.Source.SidecarConfig

	if cfg.CommandType != "docker" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCommandType, cfg.CommandType)
	}
	if cfg.Image == "" {
		return nil, fmt.Errorf("docker sidecar requires Spec.Source.SidecarConfig.Image")
	}

	port := cfg.Port
	if port == 0 {
		port = defaultSidecarPort
	}

	var replicas int32 = 1
	if adapter.Spec.Replicas != nil {
		replicas = *adapter.Spec.Replicas
	}

	labels := sidecarLabels(adapter)
	selector := sidecarSelector(adapter)

	env := append(cfg.Env, variablesToEnvVars(variables, cfg.Env)...)

	command := substituteVariables(cfg.Command, variables)
	var args []string
	for _, a := range cfg.Args {
		args = append(args, substituteVariables(a, variables))
	}

	container := corev1.Container{
		Name:  "sidecar",
		Image: cfg.Image,
		Ports: []corev1.ContainerPort{{
			Name:          "mcp",
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		}},
		Env: env,
	}
	if command != "" {
		container.Command = []string{command}
	}
	if len(args) > 0 {
		container.Args = args
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sidecarObjectName(adapter),
			Namespace: workloadNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{container},
				},
			},
		},
	}, nil
}

// needsSandbox returns true when the adapter should be backed by an
// agent-sandbox Sandbox rather than a raw Deployment. Docker/OCI images
// that already expose HTTP go through BuildDeployment; everything else
// (python, npx, go, …) gets wrapped in mcp-proxy inside a Sandbox.
func needsSandbox(adapter *mcpv1alpha1.Adapter) bool {
	if adapter.Spec.Source.SidecarConfig == nil {
		return false
	}
	return adapter.Spec.Source.SidecarConfig.CommandType != "docker"
}

// BuildSandbox renders an agent-sandbox Sandbox CR for an Adapter whose
// command type is not "docker". The Sandbox pod runs mcp-proxy in Mode 2
// (server-side), which spawns the STDIO MCP server as a child process
// and exposes streamable-HTTP on the configured port.
func BuildSandbox(adapter *mcpv1alpha1.Adapter, workloadNamespace string, variables map[string]string) (*sandboxv1alpha1.Sandbox, error) {
	if adapter.Spec.Source.SidecarConfig == nil {
		return nil, ErrMissingSidecarConfig
	}
	cfg := adapter.Spec.Source.SidecarConfig

	port := cfg.Port
	if port == 0 {
		port = defaultSidecarPort
	}

	command := substituteVariables(cfg.Command, variables)
	if command == "" {
		return nil, fmt.Errorf("sandbox adapter requires Spec.Source.SidecarConfig.Command")
	}

	image := DefaultMCPProxyImage

	proxyArgs := []string{"--port=" + strconv.Itoa(int(port))}
	// "--" separates mcp-proxy flags from the child command so
	// child args like --bugzilla-server aren't parsed by mcp-proxy.
	proxyArgs = append(proxyArgs, "--")
	proxyArgs = append(proxyArgs, strings.Fields(command)...)
	for _, a := range cfg.Args {
		proxyArgs = append(proxyArgs, substituteVariables(a, variables))
	}

	env := append(cfg.Env, variablesToEnvVars(variables, cfg.Env)...)
	labels := sidecarLabels(adapter)

	container := corev1.Container{
		Name:            "mcp-proxy",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"mcp-proxy"},
		Args:            proxyArgs,
		Ports: []corev1.ContainerPort{{
			Name:          "mcp",
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		}},
		Env: env,
	}

	return &sandboxv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sidecarObjectName(adapter),
			Namespace: workloadNamespace,
			Labels:    labels,
		},
		Spec: sandboxv1alpha1.SandboxSpec{
			Service: ptr.To(true),
			PodTemplate: sandboxv1alpha1.PodTemplate{
				Metadata: sandboxv1alpha1.PodMetadata{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{container},
				},
			},
		},
	}, nil
}

// substituteVariables replaces {{template.key}} placeholders in s with values
// from variables. Keys are env var names (e.g. BUGZILLA_SERVER); the template
// key is derived mechanically: lowercase + replace "_" with "." →
// {{bugzilla.server}}. Matches the convention in the legacy
// pkg/services/adapters/templates.go:substituteTemplates.
func substituteVariables(s string, variables map[string]string) string {
	if len(variables) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	result := s
	for envName, value := range variables {
		templateKey := strings.ToLower(strings.ReplaceAll(envName, "_", "."))
		placeholder := "{{" + templateKey + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// variablesToEnvVars converts the user-supplied Variables map into a slice
// of corev1.EnvVar, skipping any names that already exist in existing.
func variablesToEnvVars(variables map[string]string, existing []corev1.EnvVar) []corev1.EnvVar {
	if len(variables) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[e.Name] = true
	}
	var out []corev1.EnvVar
	for name, value := range variables {
		if seen[name] {
			continue
		}
		out = append(out, corev1.EnvVar{Name: name, Value: value})
	}
	return out
}

// BuildService renders the *corev1.Service exposing the Deployment built by
// BuildDeployment. Targets the same name + selector so the two are bound by
// label match, not by Service.Spec.Selector alone.
func BuildService(adapter *mcpv1alpha1.Adapter, workloadNamespace string) (*corev1.Service, error) {
	if adapter.Spec.Source.SidecarConfig == nil {
		return nil, ErrMissingSidecarConfig
	}
	cfg := adapter.Spec.Source.SidecarConfig

	port := cfg.Port
	if port == 0 {
		port = defaultSidecarPort
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sidecarObjectName(adapter),
			Namespace: workloadNamespace,
			Labels:    sidecarLabels(adapter),
		},
		Spec: corev1.ServiceSpec{
			Selector: sidecarSelector(adapter),
			Ports: []corev1.ServicePort{{
				Name:       "mcp",
				Port:       port,
				TargetPort: intstr.FromInt32(port),
				Protocol:   corev1.ProtocolTCP,
			}},
			Type: corev1.ServiceTypeClusterIP,
		},
	}, nil
}
