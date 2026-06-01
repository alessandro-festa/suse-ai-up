/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package main is the uniproxy CLI — one binary, three subcommands:
//
//   uniproxy all      (default) controller-runtime manager + HTTP shim in-process.
//                     Today's production path. Shares projection stores between
//                     reconcilers and the HTTP layer.
//   uniproxy manager  Controller-runtime manager only. Reconcilers run; no HTTP
//                     port is bound. For scaling reconcilers separately or running
//                     a "watcher only" instance.
//   uniproxy serve    HTTP shim only. shared.CRClient stays nil so bootstrap
//                     falls back to file/in-memory stores. Legacy non-operator
//                     mode for local dev. Phase-2 handlers gracefully degrade
//                     (CR-backed routes are simply not registered).
//
// The binary inside the operator image is still called suse-ai-up — the
// "uniproxy" name describes the Go package and the CLI surface, not the
// executable on disk. Renaming the executable would force a coordinated
// change across the Dockerfile, Helm chart, pod logs, and dashboards.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	sub := "all"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		sub = os.Args[1]
		// Strip the subcommand so each runner's flag.Parse sees only its
		// own flags. The dispatcher itself accepts no flags.
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	if err := dispatch(sub); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// dispatch returns nil when the chosen runner returns normally; runners
// that hit a fatal error os.Exit on their own (matching the historical
// cmd/manager behavior). Returning an error here covers the unknown-
// subcommand case so main can print and exit 2.
func dispatch(sub string) error {
	switch sub {
	case "all":
		runAll()
		return nil
	case "manager":
		runManager()
		return nil
	case "serve":
		runServe()
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("\nunknown subcommand %q", sub)
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: suse-ai-up [subcommand] [flags...]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  all      Controller-runtime manager + HTTP shim in-process (default).")
	fmt.Fprintln(w, "  manager  Controller-runtime manager only (no HTTP).")
	fmt.Fprintln(w, "  serve    HTTP shim only (no controller-runtime; legacy file-mode).")
	fmt.Fprintln(w, "  help     Print this message.")
}
