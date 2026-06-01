/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"net/http"
	"testing"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func TestEffectiveAssignments_Union(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	// explicitRefs target
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/exp", Namespace: "ns", Name: "exp"})
	// server-scoped target
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/srv", Namespace: "ns", Name: "srv", MCPServerRef: "srv1"})
	// referenced by BOTH (dedup test)
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/both", Namespace: "ns", Name: "both", MCPServerRef: "srv1"})
	// unrelated
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/other", Namespace: "ns", Name: "other"})

	got := EffectiveAssignments(s, "ns", []string{"exp", "both"}, "srv1")
	ids := func() []string {
		out := make([]string, len(got))
		for i, a := range got {
			out[i] = a.ID
		}
		return out
	}()
	wantIDs := []string{"ns/both", "ns/exp", "ns/srv"}
	if len(ids) != len(wantIDs) {
		t.Fatalf("got %v, want %v", ids, wantIDs)
	}
	for i := range wantIDs {
		if ids[i] != wantIDs[i] {
			t.Errorf("[%d] = %q, want %q (full: %v)", i, ids[i], wantIDs[i], ids)
		}
	}
}

func TestEffectiveAssignments_EmptyServerRefSkipsServerScoped(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/srv", Namespace: "ns", MCPServerRef: "srv1"})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/exp", Namespace: "ns"})

	got := EffectiveAssignments(s, "ns", []string{"exp"}, "")
	if len(got) != 1 || got[0].ID != "ns/exp" {
		t.Errorf("got %v, want [ns/exp]", idsOf(got))
	}
}

func TestEffectiveAssignments_NilRegistryReturnsNil(t *testing.T) {
	if got := EffectiveAssignments(nil, "ns", []string{"x"}, "srv1"); got != nil {
		t.Errorf("nil registry returned %v, want nil", got)
	}
}

func TestEffectiveAssignments_IgnoresEmptyAndMissingRefs(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/real", Namespace: "ns"})

	got := EffectiveAssignments(s, "ns", []string{"", "ghost", "real"}, "")
	if len(got) != 1 || got[0].ID != "ns/real" {
		t.Errorf("got %v, want [ns/real]", idsOf(got))
	}
}

func TestAllowed_EmptyAssignmentsFailOpen(t *testing.T) {
	if !Allowed("alice", []string{"admins"}, nil, mcpv1alpha1.RouteAssignmentPermissionRead) {
		t.Error("empty assignments should fail-open")
	}
}

func TestAllowed_UserMatch(t *testing.T) {
	asgs := []*RegisteredAssignment{
		{ID: "1", Users: []string{"alice"}, Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite},
	}
	if !Allowed("alice", nil, asgs, mcpv1alpha1.RouteAssignmentPermissionWrite) {
		t.Error("alice should match")
	}
	if Allowed("bob", nil, asgs, mcpv1alpha1.RouteAssignmentPermissionWrite) {
		t.Error("bob should not match")
	}
}

func TestAllowed_GroupMatch(t *testing.T) {
	asgs := []*RegisteredAssignment{
		{ID: "1", Groups: []string{"weather-team"}, Permissions: mcpv1alpha1.RouteAssignmentPermissionRead},
	}
	if !Allowed("alice", []string{"weather-team"}, asgs, mcpv1alpha1.RouteAssignmentPermissionRead) {
		t.Error("group match should allow")
	}
	if Allowed("alice", []string{"sports-team"}, asgs, mcpv1alpha1.RouteAssignmentPermissionRead) {
		t.Error("non-matching group should deny")
	}
}

func TestAllowed_PermissionHierarchy(t *testing.T) {
	cases := []struct {
		granted, required mcpv1alpha1.RouteAssignmentPermission
		want              bool
	}{
		{mcpv1alpha1.RouteAssignmentPermissionAdmin, mcpv1alpha1.RouteAssignmentPermissionAdmin, true},
		{mcpv1alpha1.RouteAssignmentPermissionAdmin, mcpv1alpha1.RouteAssignmentPermissionWrite, true},
		{mcpv1alpha1.RouteAssignmentPermissionAdmin, mcpv1alpha1.RouteAssignmentPermissionRead, true},
		{mcpv1alpha1.RouteAssignmentPermissionWrite, mcpv1alpha1.RouteAssignmentPermissionAdmin, false},
		{mcpv1alpha1.RouteAssignmentPermissionWrite, mcpv1alpha1.RouteAssignmentPermissionWrite, true},
		{mcpv1alpha1.RouteAssignmentPermissionWrite, mcpv1alpha1.RouteAssignmentPermissionRead, true},
		{mcpv1alpha1.RouteAssignmentPermissionRead, mcpv1alpha1.RouteAssignmentPermissionWrite, false},
		{mcpv1alpha1.RouteAssignmentPermissionRead, mcpv1alpha1.RouteAssignmentPermissionRead, true},
		// empty granted is treated as read (matches the reconciler's default at controllers/routeassignment_controller.go).
		{"", mcpv1alpha1.RouteAssignmentPermissionRead, true},
		{"", mcpv1alpha1.RouteAssignmentPermissionWrite, false},
	}
	for _, tc := range cases {
		asgs := []*RegisteredAssignment{{ID: "1", Users: []string{"alice"}, Permissions: tc.granted}}
		got := Allowed("alice", nil, asgs, tc.required)
		if got != tc.want {
			t.Errorf("granted=%q required=%q: got %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

func TestAllowed_EmptyUserIDStillMatchesByGroup(t *testing.T) {
	// Anonymous-ish callers (no userID, only groups inherited from a
	// federated token) should still match group-only assignments.
	asgs := []*RegisteredAssignment{
		{ID: "1", Groups: []string{"team"}, Permissions: mcpv1alpha1.RouteAssignmentPermissionRead},
	}
	if !Allowed("", []string{"team"}, asgs, mcpv1alpha1.RouteAssignmentPermissionRead) {
		t.Error("group-only match with empty userID should allow")
	}
}

func TestAllowed_EmptyUserIDInUserListDoesNotMatch(t *testing.T) {
	// An assignment that lists "" as a user should never satisfy an
	// empty caller — empty matches empty would be a footgun.
	asgs := []*RegisteredAssignment{
		{ID: "1", Users: []string{""}, Permissions: mcpv1alpha1.RouteAssignmentPermissionRead},
	}
	if Allowed("", nil, asgs, mcpv1alpha1.RouteAssignmentPermissionRead) {
		t.Error("empty user in users list should not satisfy empty caller")
	}
}

func TestMethodPermission(t *testing.T) {
	cases := map[string]mcpv1alpha1.RouteAssignmentPermission{
		http.MethodGet:     mcpv1alpha1.RouteAssignmentPermissionRead,
		http.MethodHead:    mcpv1alpha1.RouteAssignmentPermissionRead,
		http.MethodOptions: mcpv1alpha1.RouteAssignmentPermissionRead,
		http.MethodPost:    mcpv1alpha1.RouteAssignmentPermissionWrite,
		http.MethodPut:     mcpv1alpha1.RouteAssignmentPermissionWrite,
		http.MethodPatch:   mcpv1alpha1.RouteAssignmentPermissionWrite,
		http.MethodDelete:  mcpv1alpha1.RouteAssignmentPermissionWrite,
		"WHATEVER":         mcpv1alpha1.RouteAssignmentPermissionWrite,
	}
	for method, want := range cases {
		if got := MethodPermission(method); got != want {
			t.Errorf("MethodPermission(%q) = %q, want %q", method, got, want)
		}
	}
}

func idsOf(as []*RegisteredAssignment) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}
