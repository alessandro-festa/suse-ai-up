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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// ErrMissingAgentRuntime is returned when BuildAgentDeployment/Service is
// called on an Agent without Spec.Runtime. InProcess agents should not
// reach these builders — the reconciler must branch on mode first.
var ErrMissingAgentRuntime = errors.New("agent has no Spec.Runtime — InProcess mode does not build workloads")

// ErrMissingAgentImage is returned when External mode is declared but
// Spec.Runtime.Image is empty.
var ErrMissingAgentImage = errors.New("agent External mode requires Spec.Runtime.Image")

const (
	defaultAgentRuntimePort int32 = 8080

	agentManagedComponent = "agent-runtime"
	agentLabelKey         = "mcp.suse.com/agent"
)

// agentObjectName is the deterministic name shared by the Deployment and
// Service backing an Agent's external runtime. Prefix prevents collisions
// with adapter-* workloads in the same workload namespace.
func agentObjectName(agent *mcpv1alpha1.Agent) string {
	return "agent-" + agent.Name
}

// agentLabels are applied to both the Deployment's pod template and the
// Service. The agent-name label binds them together so name churn on the
// other labels doesn't break the selector pairing.
func agentLabels(agent *mcpv1alpha1.Agent) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      commonNameLabel,
		"app.kubernetes.io/component": agentManagedComponent,
		agentLabelKey:                 agent.Name,
	}
}

// agentSelector is the minimal stable subset of agentLabels used as the
// pod selector. Pod selectors are immutable, so keep this small.
func agentSelector(agent *mcpv1alpha1.Agent) map[string]string {
	return map[string]string{
		"app.kubernetes.io/component": agentManagedComponent,
		agentLabelKey:                 agent.Name,
	}
}

// BuildAgentDeployment renders the *appsv1.Deployment for an External-mode
// Agent. Pure — no client, no I/O — so it is exhaustively unit-testable.
// Caller sets OwnerReferences and applies the object.
func BuildAgentDeployment(agent *mcpv1alpha1.Agent, workloadNamespace string) (*appsv1.Deployment, error) {
	if agent.Spec.Runtime == nil {
		return nil, ErrMissingAgentRuntime
	}
	rt := agent.Spec.Runtime
	if rt.Image == "" {
		return nil, ErrMissingAgentImage
	}

	port := rt.Port
	if port == 0 {
		port = defaultAgentRuntimePort
	}

	var replicas int32 = 1
	if rt.Replicas != nil {
		replicas = *rt.Replicas
	}

	labels := agentLabels(agent)
	selector := agentSelector(agent)

	container := corev1.Container{
		Name:  "runtime",
		Image: rt.Image,
		Ports: []corev1.ContainerPort{{
			Name:          "agent",
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		}},
		Env:  rt.Env,
		Args: rt.Args,
	}
	if rt.Resources != nil {
		container.Resources = *rt.Resources
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentObjectName(agent),
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

// BuildAgentService renders the *corev1.Service exposing the runtime
// Deployment. Same selector pairing as BuildAgentDeployment.
func BuildAgentService(agent *mcpv1alpha1.Agent, workloadNamespace string) (*corev1.Service, error) {
	if agent.Spec.Runtime == nil {
		return nil, ErrMissingAgentRuntime
	}
	rt := agent.Spec.Runtime

	port := rt.Port
	if port == 0 {
		port = defaultAgentRuntimePort
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentObjectName(agent),
			Namespace: workloadNamespace,
			Labels:    agentLabels(agent),
		},
		Spec: corev1.ServiceSpec{
			Selector: agentSelector(agent),
			Ports: []corev1.ServicePort{{
				Name:       "agent",
				Port:       port,
				TargetPort: intstr.FromInt32(port),
				Protocol:   corev1.ProtocolTCP,
			}},
			Type: corev1.ServiceTypeClusterIP,
		},
	}, nil
}
