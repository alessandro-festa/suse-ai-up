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
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/services/agents"
)

// AgentReconciler validates an Agent's protocol/tool/ACL references,
// builds an external runtime Deployment+Service when Spec.Runtime is set,
// and reflects active agents into a shared in-process AgentStore. The
// per-protocol request dispatch arrives in §2.4 (HTTP shim rewire) — this
// reconciler is responsible only for registration and workload lifecycle.
type AgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// WorkloadNamespace is where External-mode Agent runtime
	// Deployments/Services are created. Reuses the AdapterReconciler
	// flag so all reconciler-owned workloads land in the same namespace.
	WorkloadNamespace string

	// Store is the in-process agent registry the reconciler reflects
	// Ready/Degraded agents into. Nil-tolerant for envtest-style suites.
	Store agents.AgentStore

	// Protocols looks up the AgentProtocol implementation for the
	// declared Spec.Protocol. Nil falls back to agents.DefaultRegistry.
	Protocols *agents.Registry
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=agents,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=agents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=agents/finalizers,verbs=update
// +kubebuilder:rbac:groups=mcp.suse.com,resources=virtualmcproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=routeassignments,verbs=get;list;watch

// Reconcile drives an Agent to its declared state. Idempotent: every call
// re-validates references and re-renders the runtime workload from
// scratch via CreateOrUpdate.
func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var agent mcpv1alpha1.Agent
	if err := r.Get(ctx, req.NamespacedName, &agent); err != nil {
		if apierrors.IsNotFound(err) {
			r.removeFromStore(ctx, agentStoreID(req.Namespace, req.Name))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching Agent: %w", err)
	}

	mode := mcpv1alpha1.AgentModeInProcess
	if agent.Spec.Runtime != nil {
		mode = mcpv1alpha1.AgentModeExternal
	}

	// Protocol validation — unknown protocol short-circuits to Failed.
	// Nothing downstream is meaningful without a known protocol.
	protocols := r.Protocols
	if protocols == nil {
		protocols = agents.DefaultRegistry
	}
	if _, known := protocols.Get(agent.Spec.Protocol); !known {
		r.removeFromStore(ctx, agentStoreID(agent.Namespace, agent.Name))
		return r.patchStatus(ctx, &agent, func(s *mcpv1alpha1.AgentStatus) {
			s.Mode = mode
			s.Phase = mcpv1alpha1.AgentPhaseFailed
			s.EndpointURL = ""
			s.RuntimeDeploymentRef = nil
			s.ObservedGeneration = agent.Generation
			setMetaCondition(&s.Conditions, agent.Generation,
				mcpv1alpha1.AgentConditionProtocolUnknown, metav1.ConditionTrue,
				"ProtocolUnknown",
				fmt.Sprintf("No AgentProtocol registered for %q (known: %s).",
					agent.Spec.Protocol, strings.Join(protocols.Names(), ", ")))
			setMetaCondition(&s.Conditions, agent.Generation,
				mcpv1alpha1.AgentConditionReady, metav1.ConditionFalse,
				"ProtocolUnknown", "Agent cannot become Ready without a known protocol.")
			setMetaCondition(&s.Conditions, agent.Generation,
				mcpv1alpha1.AgentConditionToolMissing, metav1.ConditionFalse,
				"NotEvaluated", "Tool references not evaluated — protocol unknown.")
		})
	}

	missingTools, err := r.validateTools(ctx, &agent)
	if err != nil {
		return ctrl.Result{}, err
	}
	missingACLs, err := r.validateACLs(ctx, &agent)
	if err != nil {
		return ctrl.Result{}, err
	}

	endpointURL := "/api/v1/agents/" + agent.Name

	if mode == mcpv1alpha1.AgentModeExternal && len(agent.Spec.Runtime.Env) > 0 {
		// Variable substitution is a follow-up (matches today's
		// AdapterReconciler behavior — see adapter_controller.go:107).
		logger.Info("Spec.Runtime.Env is set but variable substitution is not implemented; values pass through verbatim",
			"agent", req.NamespacedName, "envCount", len(agent.Spec.Runtime.Env))
	}

	var (
		runtimeRef       *corev1.LocalObjectReference
		observedReplicas int32
		buildErr         error
	)

	if mode == mcpv1alpha1.AgentModeExternal {
		runtimeRef, observedReplicas, buildErr = r.reconcileRuntime(ctx, &agent)
		if buildErr != nil {
			// Build errors are spec problems, not transient cluster issues;
			// surface them on Status and stop. We deliberately do NOT
			// return the error to the manager because that would trigger
			// requeue-with-backoff against an unchanged-bad spec.
			r.removeFromStore(ctx, agentStoreID(agent.Namespace, agent.Name))
			return r.patchStatus(ctx, &agent, func(s *mcpv1alpha1.AgentStatus) {
				s.Mode = mode
				s.Phase = mcpv1alpha1.AgentPhaseFailed
				s.EndpointURL = ""
				s.RuntimeDeploymentRef = nil
				s.ObservedGeneration = agent.Generation
				setMetaCondition(&s.Conditions, agent.Generation,
					mcpv1alpha1.AgentConditionReady, metav1.ConditionFalse,
					"InvalidRuntime", buildErr.Error())
				setMetaCondition(&s.Conditions, agent.Generation,
					mcpv1alpha1.AgentConditionProtocolUnknown, metav1.ConditionFalse,
					"Resolved", "Protocol is registered.")
				setMetaCondition(&s.Conditions, agent.Generation,
					mcpv1alpha1.AgentConditionToolMissing, metav1.ConditionFalse,
					"NotEvaluated", "Tool references not evaluated — runtime spec invalid.")
			})
		}
	}

	phase, readyStatus, readyReason, readyMsg := computeAgentPhase(mode, missingTools, missingACLs, observedReplicas)

	if _, patchErr := r.patchStatus(ctx, &agent, func(s *mcpv1alpha1.AgentStatus) {
		s.Mode = mode
		s.Phase = phase
		s.EndpointURL = endpointURL
		s.RuntimeDeploymentRef = runtimeRef
		s.ObservedGeneration = agent.Generation

		setMetaCondition(&s.Conditions, agent.Generation,
			mcpv1alpha1.AgentConditionReady, readyStatus, readyReason, readyMsg)
		setMetaCondition(&s.Conditions, agent.Generation,
			mcpv1alpha1.AgentConditionProtocolUnknown, metav1.ConditionFalse,
			"Resolved", "Protocol is registered.")

		toolStatus := metav1.ConditionFalse
		toolReason := "AllToolsResolved"
		toolMsg := "All referenced Adapters/VirtualMCPRoutes exist."
		if len(missingTools) > 0 {
			toolStatus = metav1.ConditionTrue
			toolReason = "ToolMissing"
			toolMsg = "Missing tool refs: " + strings.Join(missingTools, ", ")
		}
		setMetaCondition(&s.Conditions, agent.Generation,
			mcpv1alpha1.AgentConditionToolMissing, toolStatus, toolReason, toolMsg)
	}); patchErr != nil {
		return ctrl.Result{}, patchErr
	}

	if phase == mcpv1alpha1.AgentPhaseFailed {
		r.removeFromStore(ctx, agentStoreID(agent.Namespace, agent.Name))
	} else {
		r.reflectToStore(ctx, &agent, mode, endpointURL)
	}

	return ctrl.Result{}, nil
}

// reconcileRuntime builds and applies the External-mode Deployment +
// Service, then re-reads the Deployment so caller can base Phase on the
// observed AvailableReplicas.
func (r *AgentReconciler) reconcileRuntime(ctx context.Context, agent *mcpv1alpha1.Agent) (*corev1.LocalObjectReference, int32, error) {
	desiredDep, err := BuildAgentDeployment(agent, r.WorkloadNamespace)
	if err != nil {
		return nil, 0, err
	}
	desiredSvc, err := BuildAgentService(agent, r.WorkloadNamespace)
	if err != nil {
		return nil, 0, err
	}

	if err := controllerutil.SetControllerReference(agent, desiredDep, r.Scheme); err != nil {
		return nil, 0, fmt.Errorf("setting owner ref on deployment: %w", err)
	}
	if err := controllerutil.SetControllerReference(agent, desiredSvc, r.Scheme); err != nil {
		return nil, 0, fmt.Errorf("setting owner ref on service: %w", err)
	}

	depObj := &appsv1.Deployment{}
	desiredDep.DeepCopyInto(depObj)
	depObj.ResourceVersion = ""
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, depObj, func() error {
		depObj.Labels = desiredDep.Labels
		depObj.Spec = desiredDep.Spec
		depObj.OwnerReferences = desiredDep.OwnerReferences
		return nil
	}); err != nil {
		return nil, 0, fmt.Errorf("upserting deployment: %w", err)
	}

	svcObj := &corev1.Service{}
	desiredSvc.DeepCopyInto(svcObj)
	svcObj.ResourceVersion = ""
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, svcObj, func() error {
		svcObj.Labels = desiredSvc.Labels
		clusterIP := svcObj.Spec.ClusterIP
		svcObj.Spec = desiredSvc.Spec
		if clusterIP != "" {
			svcObj.Spec.ClusterIP = clusterIP
		}
		svcObj.OwnerReferences = desiredSvc.OwnerReferences
		return nil
	}); err != nil {
		return nil, 0, fmt.Errorf("upserting service: %w", err)
	}

	var observed appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(depObj), &observed); err != nil {
		return nil, 0, fmt.Errorf("reading back deployment: %w", err)
	}
	return &corev1.LocalObjectReference{Name: observed.Name}, observed.Status.AvailableReplicas, nil
}

// validateTools enforces "exactly one of AdapterRef/VirtualMCPRouteRef"
// per entry and that the referenced CR exists in the agent's namespace.
// Returns a list of missing-tool descriptors suitable for the
// ToolMissing condition message.
func (r *AgentReconciler) validateTools(ctx context.Context, agent *mcpv1alpha1.Agent) ([]string, error) {
	var missing []string
	for i, t := range agent.Spec.Tools {
		hasAdapter := t.AdapterRef != nil && t.AdapterRef.Name != ""
		hasRoute := t.VirtualMCPRouteRef != nil && t.VirtualMCPRouteRef.Name != ""
		if hasAdapter == hasRoute {
			missing = append(missing, fmt.Sprintf("tools[%d]: exactly one of adapterRef/virtualMCPRouteRef required", i))
			continue
		}
		if hasAdapter {
			var adapter mcpv1alpha1.Adapter
			if err := r.Get(ctx, types.NamespacedName{Namespace: agent.Namespace, Name: t.AdapterRef.Name}, &adapter); err != nil {
				if apierrors.IsNotFound(err) {
					missing = append(missing, "adapter/"+t.AdapterRef.Name)
					continue
				}
				return nil, fmt.Errorf("fetching Adapter %s: %w", t.AdapterRef.Name, err)
			}
		} else {
			var route mcpv1alpha1.VirtualMCPRoute
			if err := r.Get(ctx, types.NamespacedName{Namespace: agent.Namespace, Name: t.VirtualMCPRouteRef.Name}, &route); err != nil {
				if apierrors.IsNotFound(err) {
					missing = append(missing, "vroute/"+t.VirtualMCPRouteRef.Name)
					continue
				}
				return nil, fmt.Errorf("fetching VirtualMCPRoute %s: %w", t.VirtualMCPRouteRef.Name, err)
			}
		}
	}
	return missing, nil
}

// validateACLs checks each Spec.ACL[] RouteAssignment exists. Presence
// is enough — enforcement is §2.3e + §2.4.
func (r *AgentReconciler) validateACLs(ctx context.Context, agent *mcpv1alpha1.Agent) ([]string, error) {
	var missing []string
	for _, ref := range agent.Spec.ACL {
		if ref.Name == "" {
			missing = append(missing, "routeassignment/<unnamed>")
			continue
		}
		var ra mcpv1alpha1.RouteAssignment
		if err := r.Get(ctx, types.NamespacedName{Namespace: agent.Namespace, Name: ref.Name}, &ra); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, "routeassignment/"+ref.Name)
				continue
			}
			return nil, fmt.Errorf("fetching RouteAssignment %s: %w", ref.Name, err)
		}
	}
	return missing, nil
}

// computeAgentPhase rolls up the per-tool / per-ACL / runtime findings.
// Precedence: Failed > Degraded > Provisioning > Ready. Failed cases
// (protocol unknown, runtime build error) short-circuit before this
// function is reached.
func computeAgentPhase(mode mcpv1alpha1.AgentMode, missingTools, missingACLs []string, availableReplicas int32) (mcpv1alpha1.AgentPhase, metav1.ConditionStatus, string, string) {
	if len(missingTools) > 0 {
		return mcpv1alpha1.AgentPhaseDegraded,
			metav1.ConditionFalse,
			"ToolMissing",
			"Tool references not found: " + strings.Join(missingTools, ", ")
	}
	if len(missingACLs) > 0 {
		return mcpv1alpha1.AgentPhaseDegraded,
			metav1.ConditionFalse,
			"ACLMissing",
			"ACL references not found: " + strings.Join(missingACLs, ", ")
	}
	if mode == mcpv1alpha1.AgentModeExternal && availableReplicas < 1 {
		return mcpv1alpha1.AgentPhaseProvisioning,
			metav1.ConditionFalse,
			"DeploymentNotAvailable",
			"External runtime Deployment has no available replicas yet."
	}
	return mcpv1alpha1.AgentPhaseReady,
		metav1.ConditionTrue,
		"AgentReady",
		"Agent is registered and ready."
}

// patchStatus applies mutate to a fresh copy of agent.Status and issues
// a status patch. Mirrors AdapterReconciler.patchStatus.
func (r *AgentReconciler) patchStatus(ctx context.Context, agent *mcpv1alpha1.Agent, mutate func(*mcpv1alpha1.AgentStatus)) (ctrl.Result, error) {
	original := agent.DeepCopy()
	mutate(&agent.Status)
	if err := r.Status().Patch(ctx, agent, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching Agent status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *AgentReconciler) reflectToStore(ctx context.Context, agent *mcpv1alpha1.Agent, mode mcpv1alpha1.AgentMode, endpointURL string) {
	if r.Store == nil {
		return
	}
	reg := agentToRegistered(agent, mode, endpointURL)
	if err := r.Store.UpsertAgent(reg); err != nil {
		log.FromContext(ctx).Error(err, "agent store upsert failed", "agent", reg.ID)
	}
}

func (r *AgentReconciler) removeFromStore(ctx context.Context, id string) {
	if r.Store == nil {
		return
	}
	if err := r.Store.DeleteAgent(id); err != nil {
		log.FromContext(ctx).Error(err, "agent store delete failed", "agent", id)
	}
}

func agentStoreID(namespace, name string) string { return namespace + "/" + name }

// agentToRegistered projects an Agent CR into the data-plane shape the
// AgentStore holds. Lossy by design — the store is a routing table, not
// a CR mirror.
func agentToRegistered(agent *mcpv1alpha1.Agent, mode mcpv1alpha1.AgentMode, endpointURL string) *agents.RegisteredAgent {
	tools := make([]agents.ToolRef, 0, len(agent.Spec.Tools))
	for _, t := range agent.Spec.Tools {
		ref := agents.ToolRef{}
		if t.AdapterRef != nil {
			ref.AdapterName = t.AdapterRef.Name
		}
		if t.VirtualMCPRouteRef != nil {
			ref.VirtualMCPRouteName = t.VirtualMCPRouteRef.Name
		}
		if ref.AdapterName == "" && ref.VirtualMCPRouteName == "" {
			// Skip malformed entries — validateTools already reported
			// them, and the store should not see half-built refs.
			continue
		}
		tools = append(tools, ref)
	}
	return &agents.RegisteredAgent{
		ID:          agentStoreID(agent.Namespace, agent.Name),
		Namespace:   agent.Namespace,
		Name:        agent.Name,
		Protocol:    agent.Spec.Protocol,
		EndpointURL: endpointURL,
		Mode:        mode,
		Tools:       tools,
	}
}

// SetupWithManager wires the watches that re-enqueue an Agent on changes
// to its tool/ACL refs and its owned Deployment/Service.
func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.Agent{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Watches(&mcpv1alpha1.Adapter{}, handler.EnqueueRequestsFromMapFunc(r.mapAdapterToAgents)).
		Watches(&mcpv1alpha1.VirtualMCPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapRouteToAgents)).
		Watches(&mcpv1alpha1.RouteAssignment{}, handler.EnqueueRequestsFromMapFunc(r.mapAssignmentToAgents)).
		Named("agent").
		Complete(r)
}

func (r *AgentReconciler) mapAdapterToAgents(ctx context.Context, obj client.Object) []reconcile.Request {
	adapter, ok := obj.(*mcpv1alpha1.Adapter)
	if !ok {
		return nil
	}
	return r.listAgentsMatching(ctx, adapter.Namespace, func(agent *mcpv1alpha1.Agent) bool {
		for _, t := range agent.Spec.Tools {
			if t.AdapterRef != nil && t.AdapterRef.Name == adapter.Name {
				return true
			}
		}
		return false
	})
}

func (r *AgentReconciler) mapRouteToAgents(ctx context.Context, obj client.Object) []reconcile.Request {
	route, ok := obj.(*mcpv1alpha1.VirtualMCPRoute)
	if !ok {
		return nil
	}
	return r.listAgentsMatching(ctx, route.Namespace, func(agent *mcpv1alpha1.Agent) bool {
		for _, t := range agent.Spec.Tools {
			if t.VirtualMCPRouteRef != nil && t.VirtualMCPRouteRef.Name == route.Name {
				return true
			}
		}
		return false
	})
}

func (r *AgentReconciler) mapAssignmentToAgents(ctx context.Context, obj client.Object) []reconcile.Request {
	ra, ok := obj.(*mcpv1alpha1.RouteAssignment)
	if !ok {
		return nil
	}
	return r.listAgentsMatching(ctx, ra.Namespace, func(agent *mcpv1alpha1.Agent) bool {
		for _, ref := range agent.Spec.ACL {
			if ref.Name == ra.Name {
				return true
			}
		}
		return false
	})
}

func (r *AgentReconciler) listAgentsMatching(ctx context.Context, namespace string, match func(*mcpv1alpha1.Agent) bool) []reconcile.Request {
	var list mcpv1alpha1.AgentList
	if err := r.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if match(&list.Items[i]) {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: list.Items[i].Namespace,
				Name:      list.Items[i].Name,
			}})
		}
	}
	return out
}
