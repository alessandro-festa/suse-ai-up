/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5a HandleMCPProtocol ACL tests. The handler now consults
// h.assignmentRegistry when wired and rejects requests whose
// authenticated subject doesn't satisfy any effective assignment.
// These cover the four reachable outcomes:
//   - no registry  → unchanged legacy behavior (fail-open)
//   - registry, no assignments for adapter → fail-open
//   - registry, ACL present, subject matches → pass
//   - registry, ACL present, subject does not match → 403
package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
	adaptersvc "github.com/SUSE/suse-ai-up/pkg/services/adapters"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

const mcpTestNamespace = "test-ns"

// seedAdapter writes a LocalStdio AdapterResource so the handler returns
// the synthetic 200 init response (no external sidecar/remote call) when
// the ACL check passes.
func seedAdapter(t *testing.T, store clients.AdapterResourceStore, id, owner, mcpServerID string, refs []string) {
	t.Helper()
	a := models.AdapterResource{
		AdapterData: models.AdapterData{
			Name:                id,
			ConnectionType:      models.ConnectionTypeLocalStdio,
			Status:              models.AdapterLifecycleStatusReady,
			MCPServerID:         mcpServerID,
			RouteAssignmentRefs: refs,
		},
		ID:            id,
		CreatedBy:     owner,
		CreatedAt:     time.Now(),
		LastUpdatedAt: time.Now(),
	}
	if err := store.Create(context.Background(), a); err != nil {
		t.Fatalf("seed adapter: %v", err)
	}
}

// newMCPHandler constructs an AdapterHandler with the optionally-wired
// AssignmentRegistry. Callers populate the returned store/registry/users
// before invoking HandleMCPProtocol.
func newMCPHandler(t *testing.T, wireRegistry bool) (*AdapterHandler, clients.AdapterResourceStore, *authsvc.InMemoryAssignmentStore, clients.UserStore) {
	t.Helper()
	adapterStore := clients.NewInMemoryAdapterStore()
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	ugSvc := services.NewUserGroupService(userStore, groupStore)
	adapterService := adaptersvc.NewAdapterService(adapterStore, clients.NewInMemoryMCPServerStore(), nil)

	h := NewAdapterHandler(adapterService, ugSvc)
	var reg *authsvc.InMemoryAssignmentStore
	if wireRegistry {
		reg = authsvc.NewInMemoryAssignmentStore()
		h = h.WithAssignmentRegistry(reg)
		h.namespace = mcpTestNamespace
	}
	return h, adapterStore, reg, userStore
}

func mcpRequest(adapterID, userID string) *http.Request {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/adapters/"+adapterID+"/mcp", bytes.NewReader(body))
	if userID != "" {
		req.Header.Set("X-User-ID", userID)
	}
	return req
}

// --- registry not wired ----------------------------------------------------------

func TestHandleMCPProtocol_NoRegistry_PassesThrough(t *testing.T) {
	h, store, _, _ := newMCPHandler(t, false)
	seedAdapter(t, store, "a1", "dev-admin", "srv1", nil)

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("a1", "dev-admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (no registry → legacy allow-all), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- registry wired, no assignments → fail-open ----------------------------------

func TestHandleMCPProtocol_RegistryWired_NoAssignments_Allowed(t *testing.T) {
	h, store, _, _ := newMCPHandler(t, true)
	seedAdapter(t, store, "a1", "dev-admin", "srv1", nil) // adapter has no refs and no server-scoped assignments exist

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("a1", "dev-admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (no ACL → fail-open), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- registry wired, ACL via explicit ref, user listed -> 200 -------------------

func TestHandleMCPProtocol_ExplicitRef_UserMatches_Allowed(t *testing.T) {
	// Adapter owned by alice so GetAdapter's CreatedBy check passes; alice
	// is listed in the assignment's Users so the ACL check passes too.
	h, store, reg, _ := newMCPHandler(t, true)
	seedAdapter(t, store, "a1", "alice", "srv1", []string{"weather-acl"})
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: mcpTestNamespace + "/weather-acl", Namespace: mcpTestNamespace, Name: "weather-acl",
		Users:       []string{"alice"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("a1", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (alice listed in ACL), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- registry wired, ACL present, user not listed -> 403 ------------------------

func TestHandleMCPProtocol_ExplicitRef_UserNotListed_Forbidden(t *testing.T) {
	h, store, reg, userStore := newMCPHandler(t, true)
	// dev-admin owns the adapter so GetAdapter succeeds; ACL then evaluated against bob.
	seedAdapter(t, store, "a1", "dev-admin", "srv1", []string{"weather-acl"})
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: mcpTestNamespace + "/weather-acl", Namespace: mcpTestNamespace, Name: "weather-acl",
		Users:       []string{"alice"}, // bob is NOT here
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})
	// Seed bob so GetUser succeeds and userGroups is populated (bob has no groups, no match).
	_ = userStore.Create(context.Background(), models.User{ID: "bob"})

	rec := httptest.NewRecorder()
	// Use dev-admin as caller so GetAdapter passes, but the ACL check is against the caller userID — that's dev-admin.
	// dev-admin is not in any ACL, so we get 403. This is correct behavior: admin permission to MANAGE != permission to invoke.
	h.HandleMCPProtocol(rec, mcpRequest("a1", "dev-admin"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 (dev-admin not in ACL), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- registry wired, ACL present, group match -> 200 ----------------------------

func TestHandleMCPProtocol_GroupMatch_Allowed(t *testing.T) {
	h, store, reg, userStore := newMCPHandler(t, true)
	seedAdapter(t, store, "a1", "alice", "srv1", []string{"team-acl"})
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: mcpTestNamespace + "/team-acl", Namespace: mcpTestNamespace, Name: "team-acl",
		Groups:      []string{"weather-team"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
	})
	_ = userStore.Create(context.Background(), models.User{ID: "alice", Groups: []string{"weather-team"}})

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("a1", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (alice in weather-team), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- registry wired, server-scoped match via Spec.MCPServerRef -> 200 -----------

func TestHandleMCPProtocol_ServerScoped_Allowed(t *testing.T) {
	h, store, reg, _ := newMCPHandler(t, true)
	// Adapter has NO explicit RouteAssignmentRefs but binds to srv1.
	// A server-scoped assignment for srv1 should be picked up via ListByMCPServerRef.
	seedAdapter(t, store, "a1", "alice", "srv1", nil)
	_ = reg.UpsertAssignment(&authsvc.RegisteredAssignment{
		ID: mcpTestNamespace + "/srv1-acl", Namespace: mcpTestNamespace, Name: "srv1-acl",
		Users:        []string{"alice"},
		Permissions:  mcpv1alpha1.RouteAssignmentPermissionWrite,
		MCPServerRef: "srv1",
	})

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("a1", "alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (server-scoped match via Spec.MCPServerRef), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- adapter not found short-circuits before ACL --------------------------------

func TestHandleMCPProtocol_AdapterNotFound_404(t *testing.T) {
	h, _, _, _ := newMCPHandler(t, true)

	rec := httptest.NewRecorder()
	h.HandleMCPProtocol(rec, mcpRequest("ghost", "alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}
