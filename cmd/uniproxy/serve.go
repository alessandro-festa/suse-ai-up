/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"flag"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/SUSE/suse-ai-up/internal/bootstrap"
	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/httpserver"
)

// runServe is the `uniproxy serve` subcommand. HTTP shim only — no
// controller-runtime manager, no kube-apiserver connection required.
// shared.CRClient stays nil so bootstrap falls back to file/in-memory
// stores; Phase-2 handlers that need a CR client (vroutes, agents)
// gracefully degrade to "not registered" at router-construction time.
//
// Intended for legacy non-operator deployments and local dev where a
// kubernetes cluster isn't available.
func runServe() {
	// serve has its own minimal flag set — no manager / metrics / leader
	// flags are meaningful here. The zap logger plumbing is shared.
	zapOpts := zap.Options{Development: true}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	cfg := config.LoadConfig()
	runnable := httpserver.NewRunnable(cfg, bootstrap.SharedStores{})

	setupLog.Info("starting HTTP shim only (`uniproxy serve`, no controller-runtime)")
	if err := runnable.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "HTTP shim exited with error")
		os.Exit(1)
	}
}
