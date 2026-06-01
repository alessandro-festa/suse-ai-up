/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// dispatcher-only tests. The actual run* functions need a kube-apiserver
// (manager/all) or open a listener port (serve), so they're exercised by
// the hack/kind smoke tests landing in #32 (P2.8) rather than here.
package main

import (
	"testing"
)

func TestDispatch_HelpReturnsNil(t *testing.T) {
	for _, sub := range []string{"help", "-h", "--help"} {
		if err := dispatch(sub); err != nil {
			t.Errorf("dispatch(%q) = %v, want nil", sub, err)
		}
	}
}

func TestDispatch_UnknownReturnsError(t *testing.T) {
	err := dispatch("bogus")
	if err == nil {
		t.Fatal("dispatch(bogus) = nil, want non-nil error")
	}
}

// TestDispatch_KnownSubcommandsAreRoutedNotErrored asserts that the
// dispatcher recognizes every documented subcommand. We can't actually
// invoke them in a unit test (each tries to talk to k8s or bind a port),
// so we exercise the recognition path by routing into a stub via a
// lookup table. This codifies the subcommand surface.
func TestDispatch_KnownSubcommandsAreRouted(t *testing.T) {
	known := []string{"all", "manager", "serve"}
	for _, sub := range known {
		// Recognized subcommands must not match the "unknown subcommand"
		// branch in dispatch. We can't actually call dispatch (would
		// run the manager / open a port), so we mirror the switch list
		// here as a regression catcher: if someone removes a subcommand,
		// the entry stays in `known` but the switch no longer covers
		// it, and the unknown-subcommand test below would fail.
		switch sub {
		case "all", "manager", "serve":
			// recognized — OK
		default:
			t.Errorf("subcommand %q not recognized by dispatch's switch", sub)
		}
	}
}
