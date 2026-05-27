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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func newDockerAdapter(name string, mutators ...func(*mcpv1alpha1.Adapter)) *mcpv1alpha1.Adapter {
	port := int32(8080)
	replicas := int32(2)
	a := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: mcpv1alpha1.AdapterSpec{
			ConnectionType: mcpv1alpha1.ConnectionTypeSidecarStdio,
			Replicas:       &replicas,
			Source: mcpv1alpha1.AdapterSource{
				SidecarConfig: &mcpv1alpha1.SidecarConfig{
					CommandType: "docker",
					Command:     "/usr/local/bin/server",
					Args:        []string{"--port", "8080"},
					Image:       "ghcr.io/example/mcp:1.2.3",
					Port:        port,
					Env: []corev1.EnvVar{
						{Name: "MCP_LOG_LEVEL", Value: "info"},
					},
				},
			},
		},
	}
	for _, m := range mutators {
		m(a)
	}
	return a
}

func TestBuildDeployment_Docker(t *testing.T) {
	adapter := newDockerAdapter("ops")
	dep, err := BuildDeployment(adapter, "suse-ai-up-mcp")
	if err != nil {
		t.Fatalf("BuildDeployment returned error: %v", err)
	}

	if got, want := dep.Name, "adapter-ops"; got != want {
		t.Errorf("Deployment.Name = %q, want %q", got, want)
	}
	if got, want := dep.Namespace, "suse-ai-up-mcp"; got != want {
		t.Errorf("Deployment.Namespace = %q, want %q", got, want)
	}
	if got, want := *dep.Spec.Replicas, int32(2); got != want {
		t.Errorf("Replicas = %d, want %d", got, want)
	}
	if got, want := dep.Labels[adapterLabelKey], "ops"; got != want {
		t.Errorf("adapter label = %q, want %q", got, want)
	}
	if got, want := dep.Spec.Selector.MatchLabels[adapterLabelKey], "ops"; got != want {
		t.Errorf("selector adapter label = %q, want %q", got, want)
	}
	// Selector must be the subset (component + adapter), not include
	// name; it's permanent and adding labels later must not break it.
	if _, present := dep.Spec.Selector.MatchLabels["app.kubernetes.io/name"]; present {
		t.Error("selector unexpectedly includes app.kubernetes.io/name; selector should stay minimal")
	}
	if got, want := len(dep.Spec.Template.Spec.Containers), 1; got != want {
		t.Fatalf("container count = %d, want %d", got, want)
	}
	c := dep.Spec.Template.Spec.Containers[0]
	if c.Image != "ghcr.io/example/mcp:1.2.3" {
		t.Errorf("container image = %q, want %q", c.Image, "ghcr.io/example/mcp:1.2.3")
	}
	if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 8080 {
		t.Errorf("ports = %+v, want one port 8080", c.Ports)
	}
	if len(c.Command) != 1 || c.Command[0] != "/usr/local/bin/server" {
		t.Errorf("command = %v, want [/usr/local/bin/server]", c.Command)
	}
	if len(c.Args) != 2 || c.Args[0] != "--port" {
		t.Errorf("args = %v, want [--port 8080]", c.Args)
	}
	if len(c.Env) != 1 || c.Env[0].Name != "MCP_LOG_LEVEL" {
		t.Errorf("env = %+v, want MCP_LOG_LEVEL", c.Env)
	}
}

func TestBuildDeployment_DefaultsReplicasAndPort(t *testing.T) {
	adapter := newDockerAdapter("ops", func(a *mcpv1alpha1.Adapter) {
		a.Spec.Replicas = nil
		a.Spec.Source.SidecarConfig.Port = 0
	})
	dep, err := BuildDeployment(adapter, "ns")
	if err != nil {
		t.Fatalf("BuildDeployment returned error: %v", err)
	}
	if got, want := *dep.Spec.Replicas, int32(1); got != want {
		t.Errorf("default Replicas = %d, want %d", got, want)
	}
	if got, want := dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort, defaultSidecarPort; got != want {
		t.Errorf("default port = %d, want %d", got, want)
	}
}

func TestBuildDeployment_UnsupportedCommandType(t *testing.T) {
	for _, ct := range []string{"npx", "python", "pip"} {
		t.Run(ct, func(t *testing.T) {
			adapter := newDockerAdapter("ops", func(a *mcpv1alpha1.Adapter) {
				a.Spec.Source.SidecarConfig.CommandType = ct
			})
			_, err := BuildDeployment(adapter, "ns")
			if !errors.Is(err, ErrUnsupportedCommandType) {
				t.Fatalf("err = %v, want ErrUnsupportedCommandType", err)
			}
		})
	}
}

func TestBuildDeployment_MissingSidecarConfig(t *testing.T) {
	adapter := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "ops"},
		Spec: mcpv1alpha1.AdapterSpec{
			ConnectionType: mcpv1alpha1.ConnectionTypeSidecarStdio,
		},
	}
	_, err := BuildDeployment(adapter, "ns")
	if !errors.Is(err, ErrMissingSidecarConfig) {
		t.Fatalf("err = %v, want ErrMissingSidecarConfig", err)
	}
}

func TestBuildDeployment_DockerRequiresImage(t *testing.T) {
	adapter := newDockerAdapter("ops", func(a *mcpv1alpha1.Adapter) {
		a.Spec.Source.SidecarConfig.Image = ""
	})
	_, err := BuildDeployment(adapter, "ns")
	if err == nil {
		t.Fatal("expected error for missing image, got nil")
	}
	if errors.Is(err, ErrUnsupportedCommandType) || errors.Is(err, ErrMissingSidecarConfig) {
		t.Errorf("err should be a specific image-required error, got: %v", err)
	}
}

func TestBuildService_DockerMatchesDeployment(t *testing.T) {
	adapter := newDockerAdapter("ops")
	dep, err := BuildDeployment(adapter, "suse-ai-up-mcp")
	if err != nil {
		t.Fatalf("BuildDeployment: %v", err)
	}
	svc, err := BuildService(adapter, "suse-ai-up-mcp")
	if err != nil {
		t.Fatalf("BuildService: %v", err)
	}

	if svc.Name != dep.Name {
		t.Errorf("Service.Name = %q, Deployment.Name = %q (must match)", svc.Name, dep.Name)
	}
	if svc.Namespace != dep.Namespace {
		t.Errorf("Service.Namespace = %q, Deployment.Namespace = %q (must match)", svc.Namespace, dep.Namespace)
	}
	// Service selector must match the Deployment's pod template labels.
	for k, v := range svc.Spec.Selector {
		if dep.Spec.Template.Labels[k] != v {
			t.Errorf("Service selector %s=%s does not match pod label %s=%s",
				k, v, k, dep.Spec.Template.Labels[k])
		}
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8080 {
		t.Errorf("Service.Ports = %+v, want one port 8080", svc.Spec.Ports)
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("Service.Type = %q, want ClusterIP", svc.Spec.Type)
	}
}

func TestBuildService_MissingSidecarConfig(t *testing.T) {
	adapter := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{Name: "ops"},
	}
	_, err := BuildService(adapter, "ns")
	if !errors.Is(err, ErrMissingSidecarConfig) {
		t.Fatalf("err = %v, want ErrMissingSidecarConfig", err)
	}
}

func TestConnectionTypeNeedsSidecar(t *testing.T) {
	cases := map[mcpv1alpha1.ConnectionType]bool{
		mcpv1alpha1.ConnectionTypeLocalStdio:     true,
		mcpv1alpha1.ConnectionTypeSidecarStdio:   true,
		mcpv1alpha1.ConnectionTypeStreamableHTTP: true,
		mcpv1alpha1.ConnectionTypeRemoteHTTP:     false,
		mcpv1alpha1.ConnectionTypeSSE:            false,
	}
	for ct, want := range cases {
		if got := connectionTypeNeedsSidecar(ct); got != want {
			t.Errorf("connectionTypeNeedsSidecar(%q) = %v, want %v", ct, got, want)
		}
	}
}
