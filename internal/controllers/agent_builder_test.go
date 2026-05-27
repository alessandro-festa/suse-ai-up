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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func agentFixture(name string, rt *mcpv1alpha1.AgentRuntime) *mcpv1alpha1.Agent {
	return &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: mcpv1alpha1.AgentSpec{
			Protocol: "smartagents",
			Runtime:  rt,
		},
	}
}

func TestBuildAgentDeployment_MissingRuntime(t *testing.T) {
	_, err := BuildAgentDeployment(agentFixture("a", nil), "ns")
	if !errors.Is(err, ErrMissingAgentRuntime) {
		t.Errorf("err = %v, want ErrMissingAgentRuntime", err)
	}
}

func TestBuildAgentDeployment_MissingImage(t *testing.T) {
	_, err := BuildAgentDeployment(agentFixture("a", &mcpv1alpha1.AgentRuntime{Port: 8080}), "ns")
	if !errors.Is(err, ErrMissingAgentImage) {
		t.Errorf("err = %v, want ErrMissingAgentImage", err)
	}
}

func TestBuildAgentDeployment_Defaults(t *testing.T) {
	dep, err := BuildAgentDeployment(
		agentFixture("a", &mcpv1alpha1.AgentRuntime{Image: "nginx:alpine"}),
		"workload-ns",
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if dep.Namespace != "workload-ns" {
		t.Errorf("namespace = %q, want workload-ns", dep.Namespace)
	}
	if dep.Name != "agent-a" {
		t.Errorf("name = %q, want agent-a", dep.Name)
	}
	if *dep.Spec.Replicas != 1 {
		t.Errorf("replicas = %d, want 1", *dep.Spec.Replicas)
	}
	if got := dep.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort; got != defaultAgentRuntimePort {
		t.Errorf("containerPort = %d, want %d", got, defaultAgentRuntimePort)
	}
	if got := dep.Spec.Template.Spec.Containers[0].Image; got != "nginx:alpine" {
		t.Errorf("image = %q, want nginx:alpine", got)
	}
	if got := dep.Spec.Template.Spec.Containers[0].Name; got != "runtime" {
		t.Errorf("container name = %q, want runtime", got)
	}
}

func TestBuildAgentDeployment_Overrides(t *testing.T) {
	replicas := int32(3)
	rt := &mcpv1alpha1.AgentRuntime{
		Image:    "ghcr.io/example/runtime:1.2.3",
		Port:     9090,
		Replicas: &replicas,
		Args:     []string{"--verbose"},
		Env:      []corev1.EnvVar{{Name: "FOO", Value: "bar"}},
		Resources: &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
	}
	dep, err := BuildAgentDeployment(agentFixture("a", rt), "ns")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if *dep.Spec.Replicas != 3 {
		t.Errorf("replicas = %d, want 3", *dep.Spec.Replicas)
	}
	c := dep.Spec.Template.Spec.Containers[0]
	if c.Ports[0].ContainerPort != 9090 {
		t.Errorf("port = %d, want 9090", c.Ports[0].ContainerPort)
	}
	if len(c.Args) != 1 || c.Args[0] != "--verbose" {
		t.Errorf("args = %v, want [--verbose]", c.Args)
	}
	if len(c.Env) != 1 || c.Env[0].Name != "FOO" {
		t.Errorf("env = %v, want FOO=bar", c.Env)
	}
	if c.Resources.Limits.Memory().String() != "256Mi" {
		t.Errorf("memory limit = %s, want 256Mi", c.Resources.Limits.Memory().String())
	}
}

func TestBuildAgentService_Defaults(t *testing.T) {
	svc, err := BuildAgentService(
		agentFixture("a", &mcpv1alpha1.AgentRuntime{Image: "x"}),
		"workload-ns",
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if svc.Name != "agent-a" {
		t.Errorf("name = %q, want agent-a", svc.Name)
	}
	if svc.Spec.Ports[0].Port != defaultAgentRuntimePort {
		t.Errorf("port = %d, want %d", svc.Spec.Ports[0].Port, defaultAgentRuntimePort)
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("type = %q, want ClusterIP", svc.Spec.Type)
	}
}

func TestBuildAgentService_MissingRuntime(t *testing.T) {
	_, err := BuildAgentService(agentFixture("a", nil), "ns")
	if !errors.Is(err, ErrMissingAgentRuntime) {
		t.Errorf("err = %v, want ErrMissingAgentRuntime", err)
	}
}

func TestBuildAgent_SelectorPaired(t *testing.T) {
	a := agentFixture("a", &mcpv1alpha1.AgentRuntime{Image: "x"})
	dep, _ := BuildAgentDeployment(a, "ns")
	svc, _ := BuildAgentService(a, "ns")

	depSelector := dep.Spec.Selector.MatchLabels
	svcSelector := svc.Spec.Selector
	if depSelector[agentLabelKey] != "a" || svcSelector[agentLabelKey] != "a" {
		t.Errorf("agentLabelKey not paired: dep=%v svc=%v", depSelector, svcSelector)
	}
	// pod template carries the same label so the selector matches.
	if dep.Spec.Template.Labels[agentLabelKey] != "a" {
		t.Errorf("pod template missing agentLabelKey: %v", dep.Spec.Template.Labels)
	}
}
