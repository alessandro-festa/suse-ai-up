/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"os"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/SUSE/suse-ai-up/internal/bootstrap"
	"github.com/SUSE/suse-ai-up/internal/httpserver"
)

// runAll is the `uniproxy all` subcommand and the default invocation.
// Manager + HTTP shim in-process, sharing the reconciler-populated
// projection stores. This is today's production deployment shape.
func runAll() {
	opts := commonFlags()
	cmps := buildManager(opts)

	// HTTP server runs inside the operator process so handlers and
	// reconcilers share the same in-process state. The Runnable defers
	// bootstrap.BootstrapWithStores to Start time so OTEL init doesn't
	// run during wiring.
	if err := cmps.Mgr.Add(httpserver.NewRunnable(cmps.HTTPConfig, bootstrap.SharedStores{
		MCPServerStore:       cmps.MCPServerStore,
		PluginServiceManager: cmps.PluginServiceManager,
		UserStore:            cmps.UserStore,
		GroupStore:           cmps.GroupStore,
		AssignmentRegistry:   cmps.AssignmentStore,
		AgentRegistry:        cmps.AgentStore,
		CRClient:             cmps.Mgr.GetClient(),
		Namespace:            cmps.Namespace,
	})); err != nil {
		setupLog.Error(err, "unable to add HTTP server runnable")
		os.Exit(1)
	}

	setupLog.Info("starting manager + HTTP shim (`uniproxy all`)")
	if err := cmps.Mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
