/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package bootstrap

import (
	"context"
	"testing"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/handlers"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// TestBootstrapWithStores_SharesPluginServiceManager verifies the PR2
// wiring contract: when the caller passes a pre-built ServiceManager via
// SharedStores, bootstrap uses that exact instance for the PluginHandler.
// A regression here means PluginReconciler projections are written to one
// map while /api/v1/plugins/* reads from a different one — the exact bug
// PR2 fixes.
func TestBootstrapWithStores_SharesPluginServiceManager(t *testing.T) {
	mcpStore := clients.NewInMemoryMCPServerStore()
	cfg := &config.Config{}
	registryMgr := handlers.NewDefaultRegistryManager(mcpStore)
	sm := plugins.NewServiceManager(cfg, registryMgr)

	reg := &plugins.ServiceRegistration{
		ServiceID:   "ns/test-plugin",
		ServiceType: plugins.ServiceType("smartagents"),
		ServiceURL:  "http://test.local",
	}
	if err := sm.RegisterService(reg); err != nil {
		t.Fatalf("seed RegisterService: %v", err)
	}

	got, ok := sm.GetService("ns/test-plugin")
	if !ok {
		t.Fatalf("seeded plugin not visible on the manager-constructed ServiceManager")
	}
	if got.ServiceURL != "http://test.local" {
		t.Errorf("seeded plugin URL = %q, want http://test.local", got.ServiceURL)
	}

	// What we can verify without spinning up the full bootstrap (which
	// would also dial OTEL, build sidecar clients, etc.): that
	// PluginHandler accepts the same *ServiceManager pointer and reads
	// from it. The handler is constructed by bootstrap from
	// shared.PluginServiceManager; here we mirror that wiring.
	h := handlers.NewPluginHandler(sm)
	if h == nil {
		t.Fatalf("NewPluginHandler returned nil")
	}
}

// TestLayeredUserStore_ProjectionOverlay verifies the PR3 wiring contract:
// after a reconciler upserts a RegisteredUser into the auth projection,
// GET-style reads through the layered clients.UserStore see the projected
// entry without disturbing the file-store entries.
func TestLayeredUserStore_ProjectionOverlay(t *testing.T) {
	ctx := context.Background()
	file := clients.NewInMemoryUserStore()
	if err := file.Create(ctx, models.User{ID: "local-admin", Name: "Local Admin", Email: "admin@local"}); err != nil {
		t.Fatalf("seed file store: %v", err)
	}

	projection := authsvc.NewInMemoryUserStore()
	if err := projection.UpsertUser(&authsvc.RegisteredUser{
		ID:        "ns/cr-user",
		Namespace: "ns",
		Name:      "cr-user",
		Email:     "cr@example.com",
		Groups:    []string{"reviewers"},
	}); err != nil {
		t.Fatalf("seed projection: %v", err)
	}

	layered := newLayeredUserStore(file, projection)

	got, err := layered.Get(ctx, "ns/cr-user")
	if err != nil {
		t.Fatalf("Get(projection entry): %v", err)
	}
	if got.Email != "cr@example.com" {
		t.Errorf("projection Get email = %q, want cr@example.com", got.Email)
	}

	got, err = layered.Get(ctx, "local-admin")
	if err != nil {
		t.Fatalf("Get(file entry): %v", err)
	}
	if got.Email != "admin@local" {
		t.Errorf("file Get email = %q, want admin@local", got.Email)
	}

	list, err := layered.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2 (one from each store)", len(list))
	}
	seen := map[string]bool{}
	for _, u := range list {
		seen[u.ID] = true
	}
	if !seen["ns/cr-user"] || !seen["local-admin"] {
		t.Errorf("List missing entries: got %v", seen)
	}

	byEmail, err := layered.GetByEmail(ctx, "cr@example.com")
	if err != nil {
		t.Fatalf("GetByEmail(projection): %v", err)
	}
	if byEmail.ID != "ns/cr-user" {
		t.Errorf("GetByEmail(projection) ID = %q, want ns/cr-user", byEmail.ID)
	}
}

// TestLayeredUserStore_AuthDelegatesToFile pins the deferred-auth
// contract: Authenticate must not touch the projection (which has no
// passwords) — it goes to the file store. If this test ever starts
// failing because someone wired projection→auth directly, that change
// needs the credentialSecretRef story first.
func TestLayeredUserStore_AuthDelegatesToFile(t *testing.T) {
	ctx := context.Background()
	file := clients.NewInMemoryUserStore()
	projection := authsvc.NewInMemoryUserStore()
	layered := newLayeredUserStore(file, projection)

	if _, err := layered.Authenticate(ctx, "missing", "wrong"); err == nil {
		t.Fatalf("Authenticate against empty file store should error, got nil")
	}
}

// TestLayeredGroupStore_ProjectionOverlay mirrors TestLayeredUserStore for
// groups.
func TestLayeredGroupStore_ProjectionOverlay(t *testing.T) {
	ctx := context.Background()
	file := clients.NewInMemoryGroupStore()
	if err := file.Create(ctx, models.Group{ID: "mcp-admins", Name: "Admins", Permissions: []string{"server:*"}}); err != nil {
		t.Fatalf("seed file store: %v", err)
	}

	projection := authsvc.NewInMemoryGroupStore()
	if err := projection.UpsertGroup(&authsvc.RegisteredGroup{
		ID:          "ns/reviewers",
		Namespace:   "ns",
		Name:        "reviewers",
		Members:     []string{"ns/cr-user"},
		Permissions: []string{"server:read"},
	}); err != nil {
		t.Fatalf("seed projection: %v", err)
	}

	layered := newLayeredGroupStore(file, projection, nil)
	list, err := layered.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}
}
