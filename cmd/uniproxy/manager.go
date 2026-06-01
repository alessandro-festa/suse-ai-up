/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/controllers"
	"github.com/SUSE/suse-ai-up/internal/handlers"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
	"github.com/SUSE/suse-ai-up/pkg/services/agents"
	"github.com/SUSE/suse-ai-up/pkg/services/auth"
	"github.com/SUSE/suse-ai-up/pkg/services/virtualmcp"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(mcpv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// managerOpts holds the parsed values from commonFlags. Shared between
// runAll and runManager so both subcommands take the same flag set.
type managerOpts struct {
	MetricsAddr          string
	ProbeAddr            string
	EnableLeaderElection bool
	SecureMetrics        bool
	EnableHTTP2          bool
	WorkloadNamespace    string
}

// commonFlags registers the kube/auth flags shared by the manager and
// all subcommands and returns the populated managerOpts after Parse.
// Also installs the zap logger.
func commonFlags() managerOpts {
	var opts managerOpts
	flag.StringVar(&opts.MetricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&opts.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&opts.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&opts.SecureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&opts.EnableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&opts.WorkloadNamespace, "workload-namespace", "suse-ai-up-mcp",
		"Namespace where adapter Deployments/Services are created.")
	zapOpts := zap.Options{Development: true}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	return opts
}

// managerComponents bundles the controller-runtime Manager together with
// the in-process stores it populates. runAll passes these into the HTTP
// shim's SharedStores so handlers and reconcilers share state; runManager
// drops the stores on the floor (the manager binary is correct without
// them, just wasteful — reconciling CRs into stores no consumer reads).
type managerComponents struct {
	Mgr                  manager.Manager
	MCPServerStore       clients.MCPServerStore
	UserStore            *auth.InMemoryUserStore
	GroupStore           *auth.InMemoryGroupStore
	AssignmentStore      *auth.InMemoryAssignmentStore
	AgentStore           *agents.InMemoryAgentStore
	RouteStore           *virtualmcp.InMemoryRouteStore
	PluginServiceManager *plugins.ServiceManager
	HTTPConfig           *config.Config
	Namespace            string
}

// buildManager constructs the controller-runtime Manager and registers
// every reconciler. Shared by runManager and runAll. Hard-exits via
// setupLog on any failure — keeps the historical fail-fast behavior of
// the pre-refactor cmd/manager.
func buildManager(opts managerOpts) managerComponents {
	tlsOpts := []func(*tls.Config){}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	if !opts.EnableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{TLSOpts: tlsOpts})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   opts.MetricsAddr,
		SecureServing: opts.SecureMetrics,
		TLSOpts:       tlsOpts,
	}
	if opts.SecureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'.
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: opts.ProbeAddr,
		LeaderElection:         opts.EnableLeaderElection,
		LeaderElectionID:       "d0141a56.suse.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// AdapterReconciler — sidecar Deployment+Service ownership.
	if err = (&controllers.AdapterReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		WorkloadNamespace: opts.WorkloadNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "Adapter")
		os.Exit(1)
	}

	// In-process MCP server cache. The HTTP shim (P2.4) consumes this
	// via SharedStores so the controller and the HTTP path see the same
	// servers.
	mcpServerStore := clients.NewInMemoryMCPServerStore()

	if err = (&controllers.MCPRegistryReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "MCPRegistry")
		os.Exit(1)
	}
	if err = (&controllers.MCPServerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  mcpServerStore,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "MCPServer")
		os.Exit(1)
	}

	// Composed-route table the reconciler reflects Ready/Degraded virtual
	// routes into. NoOp capability provider for now — §2.4 swaps in a real
	// implementation backed by the capability cache, no controller change
	// required.
	routeStore := virtualmcp.NewInMemoryRouteStore()
	capabilityProvider := virtualmcp.NewNoOpCapabilityProvider()

	if err = (&controllers.VirtualMCPRouteReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Store:    routeStore,
		Provider: capabilityProvider,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "VirtualMCPRoute")
		os.Exit(1)
	}

	// In-process Agent registry the HTTP shim (P2.5c) shares for
	// request-time agent lookup. agents.DefaultRegistry holds the
	// AgentProtocol implementations the reconciler validates
	// Spec.Protocol against.
	agentStore := agents.NewInMemoryAgentStore()

	if err = (&controllers.AgentReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		WorkloadNamespace: opts.WorkloadNamespace,
		Store:             agentStore,
		Protocols:         agents.DefaultRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "Agent")
		os.Exit(1)
	}

	// In-process auth projection stores. The reconcilers reflect the
	// validated CR state here; the HTTP shim consumes them so request-time
	// permission checks see the live cluster state.
	userStore := auth.NewInMemoryUserStore()
	groupStore := auth.NewInMemoryGroupStore()
	assignmentStore := auth.NewInMemoryAssignmentStore()

	if err = (&controllers.UserReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  userStore,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "User")
		os.Exit(1)
	}
	if err = (&controllers.GroupReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  groupStore,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "Group")
		os.Exit(1)
	}
	if err = (&controllers.RouteAssignmentReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  assignmentStore,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "RouteAssignment")
		os.Exit(1)
	}

	// Plugin registry shared between PluginReconciler and the HTTP
	// PluginHandler. DefaultRegistryManager is a stateless wrapper over
	// mcpServerStore; bootstrap builds another one for the registry-admin
	// path — they share the underlying store, so both views stay coherent.
	httpCfg := config.LoadConfig()
	pluginRegistryManager := handlers.NewDefaultRegistryManager(mcpServerStore)
	pluginServiceManager := plugins.NewServiceManager(httpCfg, pluginRegistryManager)

	if err = (&controllers.PluginReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Prober:          controllers.NewProber(nil),
		Store:           pluginServiceManager,
		DefaultInterval: 30 * time.Second,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", "Plugin")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	return managerComponents{
		Mgr:                  mgr,
		MCPServerStore:       mcpServerStore,
		UserStore:            userStore,
		GroupStore:           groupStore,
		AssignmentStore:      assignmentStore,
		AgentStore:           agentStore,
		RouteStore:           routeStore,
		PluginServiceManager: pluginServiceManager,
		HTTPConfig:           httpCfg,
		Namespace:            opts.WorkloadNamespace,
	}
}

// runManager is the `uniproxy manager` subcommand. Builds the manager
// without the HTTP runnable. The stores are still populated by the
// reconcilers but no in-process consumer reads them — fine for a
// manager-only deployment whose only job is reconciling CRs into owned
// k8s resources.
func runManager() {
	opts := commonFlags()
	cmps := buildManager(opts)

	setupLog.Info("starting manager (no HTTP shim — `uniproxy manager`)")
	if err := cmps.Mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
