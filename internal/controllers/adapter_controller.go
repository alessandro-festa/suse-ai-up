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
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sandboxv1alpha1 "github.com/SUSE/suse-ai-up/api/sandbox/v1alpha1"
	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// AdapterReconciler reconciles an Adapter into a backing Deployment+Service
// (for sidecar-style ConnectionTypes) and keeps Status in sync. Pure
// remote/HTTP adapters short-circuit to status-only reconciliation since the
// proxy talks directly to the upstream.
type AdapterReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// WorkloadNamespace is where this reconciler creates the
	// Deployment+Service backing each Adapter. Injected at construction so
	// tests and clusters can use different namespaces without rebuilding.
	WorkloadNamespace string
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=adapters,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=adapters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=adapters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=agents.x-k8s.io,resources=sandboxes,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives the Adapter toward its declared state. The loop is
// idempotent: every call computes the desired Deployment/Service shape from
// scratch and asks controllerutil.CreateOrUpdate to converge. OwnerReferences
// on the children mean Adapter deletion cascades automatically; no
// finalizer is needed at this stage.
func (r *AdapterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var adapter mcpv1alpha1.Adapter
	if err := r.Get(ctx, req.NamespacedName, &adapter); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching Adapter: %w", err)
	}

	endpointURL := fmt.Sprintf("/api/v1/adapters/%s/mcp", adapter.Name)

	// Remote / pure-HTTP adapters have no backing workload — the proxy
	// dials the upstream directly. Mark Ready and return.
	if !connectionTypeNeedsSidecar(adapter.Spec.ConnectionType) {
		return r.patchStatus(ctx, &adapter, func(s *mcpv1alpha1.AdapterStatus) {
			s.Phase = mcpv1alpha1.AdapterPhaseReady
			s.EndpointURL = endpointURL
			s.SidecarDeploymentRef = nil
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionTrue,
				"NoSidecarRequired", "Connection type does not require a sidecar workload.")
			setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionTrue,
				"InSync", "Adapter is fully reconciled.")
			s.ObservedGeneration = adapter.Generation
		})
	}

	// Sidecar connection types from here on. SidecarConfig validation
	// happens up-front so a misconfigured CR fails fast on Status rather
	// than producing a half-built Deployment.
	if adapter.Spec.Source.SidecarConfig == nil {
		logger.Info("Adapter requires sidecar but Spec.Source.SidecarConfig is nil", "adapter", req.NamespacedName)
		return r.patchStatus(ctx, &adapter, func(s *mcpv1alpha1.AdapterStatus) {
			s.Phase = mcpv1alpha1.AdapterPhaseFailed
			s.EndpointURL = ""
			setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionFalse,
				"MissingSidecarConfig", "Spec.Source.SidecarConfig is required for this ConnectionType.")
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionFalse,
				"MissingSidecarConfig", "Adapter cannot become Ready without a SidecarConfig.")
			s.ObservedGeneration = adapter.Generation
		})
	}

	// Dispatch: Sandbox (mcp-proxy wrapping STDIO servers) vs Deployment
	// (raw docker image that already speaks HTTP).
	if needsSandbox(&adapter) {
		return r.reconcileSandbox(ctx, &adapter, endpointURL)
	}
	return r.reconcileDeployment(ctx, &adapter, endpointURL)
}

// reconcileDeployment handles the Deployment+Service path for docker-type
// adapters (the original code path, extracted for dispatch clarity).
func (r *AdapterReconciler) reconcileDeployment(ctx context.Context, adapter *mcpv1alpha1.Adapter, endpointURL string) (ctrl.Result, error) {
	desiredDep, err := BuildDeployment(adapter, r.WorkloadNamespace, adapter.Spec.Variables)
	if err != nil {
		reason, msg := classifyBuildError(err)
		log.FromContext(ctx).Info("Adapter spec is not buildable by this reconciler",
			"adapter", client.ObjectKeyFromObject(adapter), "reason", reason, "error", err.Error())
		return r.patchStatus(ctx, adapter, func(s *mcpv1alpha1.AdapterStatus) {
			s.Phase = mcpv1alpha1.AdapterPhaseFailed
			s.EndpointURL = ""
			setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionFalse, reason, msg)
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionFalse, reason, msg)
			s.ObservedGeneration = adapter.Generation
		})
	}

	desiredSvc, err := BuildService(adapter, r.WorkloadNamespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("building service: %w", err)
	}

	if err := controllerutil.SetControllerReference(adapter, desiredDep, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting owner ref on deployment: %w", err)
	}
	if err := controllerutil.SetControllerReference(adapter, desiredSvc, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting owner ref on service: %w", err)
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
		return ctrl.Result{}, fmt.Errorf("upserting deployment: %w", err)
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
		return ctrl.Result{}, fmt.Errorf("upserting service: %w", err)
	}

	var observedDep appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(depObj), &observedDep); err != nil {
		return ctrl.Result{}, fmt.Errorf("reading back deployment for status: %w", err)
	}

	return r.patchStatus(ctx, adapter, func(s *mcpv1alpha1.AdapterStatus) {
		s.EndpointURL = endpointURL
		s.SidecarDeploymentRef = &corev1.LocalObjectReference{Name: observedDep.Name}
		s.ObservedGeneration = adapter.Generation

		ready := observedDep.Status.AvailableReplicas >= 1
		if ready {
			s.Phase = mcpv1alpha1.AdapterPhaseReady
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionTrue,
				"DeploymentAvailable", fmt.Sprintf("Deployment %s has %d available replica(s).",
					observedDep.Name, observedDep.Status.AvailableReplicas))
		} else {
			s.Phase = mcpv1alpha1.AdapterPhaseProvisioning
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionFalse,
				"DeploymentNotAvailable", fmt.Sprintf("Deployment %s has no available replicas yet.", observedDep.Name))
		}
		setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionTrue,
			"InSync", "Deployment and Service reconciled to desired state.")
	})
}

// reconcileSandbox handles the agent-sandbox Sandbox path for non-docker
// adapters. The Sandbox pod runs mcp-proxy wrapping the STDIO MCP server;
// agent-sandbox creates a ClusterIP Service automatically when
// Spec.Service=true.
func (r *AdapterReconciler) reconcileSandbox(ctx context.Context, adapter *mcpv1alpha1.Adapter, endpointURL string) (ctrl.Result, error) {
	desiredSandbox, err := BuildSandbox(adapter, r.WorkloadNamespace, adapter.Spec.Variables)
	if err != nil {
		reason, msg := classifyBuildError(err)
		log.FromContext(ctx).Info("Adapter spec is not buildable as Sandbox",
			"adapter", client.ObjectKeyFromObject(adapter), "reason", reason, "error", err.Error())
		return r.patchStatus(ctx, adapter, func(s *mcpv1alpha1.AdapterStatus) {
			s.Phase = mcpv1alpha1.AdapterPhaseFailed
			s.EndpointURL = ""
			setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionFalse, reason, msg)
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionFalse, reason, msg)
			s.ObservedGeneration = adapter.Generation
		})
	}

	if err := controllerutil.SetControllerReference(adapter, desiredSandbox, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting owner ref on sandbox: %w", err)
	}

	sbxObj := &sandboxv1alpha1.Sandbox{}
	desiredSandbox.DeepCopyInto(sbxObj)
	sbxObj.ResourceVersion = ""
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, sbxObj, func() error {
		sbxObj.Labels = desiredSandbox.Labels
		sbxObj.Spec = desiredSandbox.Spec
		sbxObj.OwnerReferences = desiredSandbox.OwnerReferences
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("upserting sandbox: %w", err)
	}

	var observedSandbox sandboxv1alpha1.Sandbox
	if err := r.Get(ctx, client.ObjectKeyFromObject(sbxObj), &observedSandbox); err != nil {
		return ctrl.Result{}, fmt.Errorf("reading back sandbox for status: %w", err)
	}

	return r.patchStatus(ctx, adapter, func(s *mcpv1alpha1.AdapterStatus) {
		s.EndpointURL = endpointURL
		s.SidecarDeploymentRef = &corev1.LocalObjectReference{Name: observedSandbox.Name}
		s.ObservedGeneration = adapter.Generation

		ready := sandboxIsReady(&observedSandbox)
		if ready {
			s.Phase = mcpv1alpha1.AdapterPhaseReady
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionTrue,
				"SandboxReady", fmt.Sprintf("Sandbox %s is ready.", observedSandbox.Name))
		} else {
			s.Phase = mcpv1alpha1.AdapterPhaseProvisioning
			setCondition(s, mcpv1alpha1.AdapterConditionReady, metav1.ConditionFalse,
				"SandboxNotReady", fmt.Sprintf("Sandbox %s is not ready yet.", observedSandbox.Name))
		}
		setCondition(s, mcpv1alpha1.AdapterConditionSynced, metav1.ConditionTrue,
			"InSync", "Sandbox reconciled to desired state.")
	})
}

// sandboxIsReady checks the agent-sandbox Sandbox status conditions for
// a "Ready" condition with status True.
func sandboxIsReady(sbx *sandboxv1alpha1.Sandbox) bool {
	for _, c := range sbx.Status.Conditions {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// classifyBuildError maps a builder error to a stable (Reason, Message) pair
// for the Status condition.
func classifyBuildError(err error) (string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedCommandType):
		return "UnsupportedCommandType", err.Error()
	case errors.Is(err, ErrMissingSidecarConfig):
		return "MissingSidecarConfig", err.Error()
	default:
		return "InvalidSpec", err.Error()
	}
}

// patchStatus applies mutate to a fresh copy of adapter.Status, then issues
// a status patch. Returning the resulting Result/error lets callers `return
// r.patchStatus(...)` directly.
func (r *AdapterReconciler) patchStatus(ctx context.Context, adapter *mcpv1alpha1.Adapter, mutate func(*mcpv1alpha1.AdapterStatus)) (ctrl.Result, error) {
	original := adapter.DeepCopy()
	mutate(&adapter.Status)
	if err := r.Status().Patch(ctx, adapter, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching status: %w", err)
	}
	return ctrl.Result{}, nil
}

// setCondition is a thin wrapper that finds-or-appends a Condition by Type
// and stamps LastTransitionTime when Status flips. Kept private until other
// reconcilers need it; will be promoted to a shared helper when reused.
func setCondition(status *mcpv1alpha1.AdapterStatus, condType string, condStatus metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i := range status.Conditions {
		if status.Conditions[i].Type != condType {
			continue
		}
		c := &status.Conditions[i]
		if c.Status != condStatus {
			c.LastTransitionTime = now
		}
		c.Status = condStatus
		c.Reason = reason
		c.Message = message
		c.ObservedGeneration = status.ObservedGeneration
		return
	}
	status.Conditions = append(status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: status.ObservedGeneration,
	})
}

// SetupWithManager registers the reconciler with the controller manager and
// declares the owned types so deletion cascades via OwnerReferences and
// Deployment/Service updates re-trigger Reconcile.
func (r *AdapterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.Adapter{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&sandboxv1alpha1.Sandbox{}).
		Named("adapter").
		Complete(r)
}
