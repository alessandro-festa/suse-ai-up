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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
)

const (
	// defaultPluginHealthPath, defaultPluginIntervalSec, and
	// defaultPluginTimeoutSec mirror the CRD defaults documented on
	// PluginHealthCheck. Duplicated here because the reconciler computes
	// effective values before any defaulting admission webhook runs.
	defaultPluginHealthPath  = "/health"
	defaultPluginIntervalSec = 30
	defaultPluginTimeoutSec  = 5
)

// PluginReconciler probes registered Plugin CRs on the cadence declared in
// Spec.HealthCheck, reflects health and discovered capabilities into
// Status, and projects active plugins into a shared in-process Store the
// proxy data plane consults at request time. Health probing relies on
// controller-runtime's RequeueAfter — no per-CR goroutines.
type PluginReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Prober runs the health probe and capability discovery. Nil falls
	// back to a default Prober with a 30s-timeout http.Client; tests can
	// inject a fake to skip the real HTTP call.
	Prober PluginProber

	// Store is the in-process plugin registry the reconciler projects
	// into. *plugins.ServiceManager satisfies it. Nil is tolerated so
	// the manager binary can stand up the reconciler before the data
	// plane wiring (P2.4) is in place.
	Store plugins.PluginServiceManager

	// DefaultInterval is the requeue cadence used when Spec.HealthCheck
	// is nil or IntervalSeconds is zero. Matches the CRD default of 30s.
	DefaultInterval time.Duration
}

// +kubebuilder:rbac:groups=mcp.suse.com,resources=plugins,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=plugins/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mcp.suse.com,resources=plugins/finalizers,verbs=update

// Reconcile drives one Plugin toward its declared state. Idempotent: every
// call re-probes the plugin, re-projects the registration, and requeues
// itself at the configured interval. On NotFound, the projection is
// removed from the in-process store so the data plane stops routing to it.
func (r *PluginReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var plugin mcpv1alpha1.Plugin
	if err := r.Get(ctx, req.NamespacedName, &plugin); err != nil {
		if apierrors.IsNotFound(err) {
			r.removeFromStore(ctx, pluginStoreID(req.Namespace, req.Name))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching Plugin: %w", err)
	}

	path, intervalSec, timeoutSec := effectiveHealthCheck(plugin.Spec.HealthCheck)
	interval := time.Duration(intervalSec) * time.Second
	timeout := time.Duration(timeoutSec) * time.Second

	prober := r.prober()
	result := prober.Probe(ctx, plugin.Spec.ServiceType, plugin.Spec.ServiceURL, path, timeout)

	// Capability discovery is best-effort: a virtualmcp plugin can be
	// reachable on /health but transiently fail /api/v1/mcps. Mirrors
	// pkg/plugins/manager.go:syncVirtualMCP — discovery errors are
	// logged, not surfaced on the CR.
	observedCaps := plugin.Status.ObservedCapabilities
	if plugin.Spec.ServiceType == mcpv1alpha1.PluginServiceTypeVirtualMCP && result.Healthy {
		caps, err := prober.DiscoverCapabilities(ctx, pluginStoreID(plugin.Namespace, plugin.Name), plugin.Spec.ServiceURL)
		if err != nil {
			logger.Info("virtualmcp capability discovery failed; keeping previous ObservedCapabilities",
				"plugin", req.NamespacedName, "error", err.Error())
		} else {
			observedCaps = caps
		}
	}

	registeredAt := plugin.Status.RegisteredAt
	if registeredAt == nil {
		now := metav1.Now()
		registeredAt = &now
	}

	r.reflectToStore(ctx, &plugin, result.Healthy, observedCaps, registeredAt)

	lastChecked := metav1.Now()
	phase := computePluginPhase(plugin.Spec.ServiceURL, result.Healthy, plugin.Status.RegisteredAt != nil)

	if _, err := r.patchStatus(ctx, &plugin, func(s *mcpv1alpha1.PluginStatus) {
		s.Phase = phase
		s.Healthy = result.Healthy
		s.LastHealthCheckTime = &lastChecked
		s.LastHealthCheckMessage = ""
		if !result.Healthy {
			s.LastHealthCheckMessage = result.Message
		}
		s.ResponseTimeMillis = result.ResponseTime.Milliseconds()
		s.ObservedCapabilities = observedCaps
		s.RegisteredAt = registeredAt
		s.ObservedGeneration = plugin.Generation

		readyStatus := metav1.ConditionFalse
		readyReason := "ProbeFailed"
		readyMsg := result.Message
		if result.Healthy {
			readyStatus = metav1.ConditionTrue
			readyReason = "PluginHealthy"
			readyMsg = "Plugin health probe succeeded."
		}
		setMetaCondition(&s.Conditions, plugin.Generation,
			mcpv1alpha1.PluginConditionReady, readyStatus, readyReason, readyMsg)

		setMetaCondition(&s.Conditions, plugin.Generation,
			mcpv1alpha1.PluginConditionRegistered, metav1.ConditionTrue,
			"Projected", "Plugin is projected into the in-process plugin registry.")

		healthyStatus := metav1.ConditionFalse
		healthyReason := "ProbeFailed"
		healthyMsg := result.Message
		if result.Healthy {
			healthyStatus = metav1.ConditionTrue
			healthyReason = "ProbeSucceeded"
			healthyMsg = result.Message
		}
		setMetaCondition(&s.Conditions, plugin.Generation,
			mcpv1alpha1.PluginConditionHealthy, healthyStatus, healthyReason, healthyMsg)
	}); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: interval}, nil
}

// effectiveHealthCheck applies the CRD-documented defaults to a possibly
// nil PluginHealthCheck. Returning primitives keeps the call site
// readable; the reconciler doesn't care about the spec shape.
func effectiveHealthCheck(hc *mcpv1alpha1.PluginHealthCheck) (path string, intervalSec, timeoutSec int32) {
	path = defaultPluginHealthPath
	intervalSec = defaultPluginIntervalSec
	timeoutSec = defaultPluginTimeoutSec
	if hc == nil {
		return
	}
	if hc.Path != "" {
		path = hc.Path
	}
	if hc.IntervalSeconds > 0 {
		intervalSec = hc.IntervalSeconds
	}
	if hc.TimeoutSeconds > 0 {
		timeoutSec = hc.TimeoutSeconds
	}
	return
}

// computePluginPhase rolls up the spec/probe state into the public Phase
// enum. Precedence: Failed (invalid spec) > Healthy > Unhealthy (probe
// failed after registration) > Registered (probe failed on first
// reconcile). Pending is reserved for the brief window before this
// reconciler runs; we never persist it.
func computePluginPhase(serviceURL string, healthy, previouslyRegistered bool) mcpv1alpha1.PluginPhase {
	if serviceURL == "" {
		return mcpv1alpha1.PluginPhaseFailed
	}
	if healthy {
		return mcpv1alpha1.PluginPhaseHealthy
	}
	if previouslyRegistered {
		return mcpv1alpha1.PluginPhaseUnhealthy
	}
	return mcpv1alpha1.PluginPhaseRegistered
}

// patchStatus applies mutate to a fresh copy of plugin.Status and issues
// a status patch. Mirrors AdapterReconciler.patchStatus.
func (r *PluginReconciler) patchStatus(ctx context.Context, plugin *mcpv1alpha1.Plugin, mutate func(*mcpv1alpha1.PluginStatus)) (ctrl.Result, error) {
	original := plugin.DeepCopy()
	mutate(&plugin.Status)
	if err := r.Status().Patch(ctx, plugin, client.MergeFrom(original)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patching Plugin status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *PluginReconciler) prober() PluginProber {
	if r.Prober != nil {
		return r.Prober
	}
	return NewProber(nil)
}

func (r *PluginReconciler) reflectToStore(ctx context.Context, plugin *mcpv1alpha1.Plugin, healthy bool, caps []mcpv1alpha1.PluginCapability, registeredAt *metav1.Time) {
	if r.Store == nil {
		return
	}
	reg := pluginToRegistration(plugin, caps, registeredAt)
	if err := r.Store.RegisterService(reg); err != nil {
		log.FromContext(ctx).Error(err, "plugin store register failed", "plugin", reg.ServiceID)
		return
	}
	healthStatus := "unhealthy"
	if healthy {
		healthStatus = "healthy"
	}
	r.Store.UpdateServiceHealth(reg.ServiceID, plugins.ServiceHealth{
		Status:      healthStatus,
		LastChecked: time.Now(),
	})
}

func (r *PluginReconciler) removeFromStore(ctx context.Context, id string) {
	if r.Store == nil {
		return
	}
	if err := r.Store.UnregisterService(id); err != nil {
		log.FromContext(ctx).Error(err, "plugin store unregister failed", "plugin", id)
	}
}

func pluginStoreID(namespace, name string) string { return namespace + "/" + name }

// pluginToRegistration projects a Plugin CR into the wire shape
// *plugins.ServiceManager expects. Lossy by design — the store is a
// routing table keyed by ServiceID, not a CR mirror. Status fields stay
// on the CR.
func pluginToRegistration(plugin *mcpv1alpha1.Plugin, observed []mcpv1alpha1.PluginCapability, registeredAt *metav1.Time) *plugins.ServiceRegistration {
	caps := observed
	if len(caps) == 0 {
		caps = plugin.Spec.Capabilities
	}
	out := make([]plugins.ServiceCapability, 0, len(caps))
	for _, c := range caps {
		out = append(out, plugins.ServiceCapability{
			Path:        c.Path,
			Methods:     append([]string(nil), c.Methods...),
			Description: c.Description,
		})
	}
	reg := &plugins.ServiceRegistration{
		ServiceID:    pluginStoreID(plugin.Namespace, plugin.Name),
		ServiceType:  plugins.ServiceType(plugin.Spec.ServiceType),
		ServiceURL:   plugin.Spec.ServiceURL,
		Capabilities: out,
		Version:      plugin.Spec.Version,
	}
	if registeredAt != nil {
		reg.RegisteredAt = registeredAt.Time
	}
	reg.LastHeartbeat = time.Now()
	return reg
}

// SetupWithManager registers the reconciler. Plugin owns no children and
// references no other CRs, so the watch graph is just the Plugin itself.
func (r *PluginReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.Plugin{}).
		Named("plugin").
		Complete(r)
}
