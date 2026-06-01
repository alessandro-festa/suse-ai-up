/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5a authorization helpers consumed by the proxy hot paths.
//
// EffectiveAssignments computes the union of explicit
// Adapter.Spec.RouteAssignmentRefs and server-scoped assignments
// populated via Spec.MCPServerRef (the P2.4i bridge). Allowed evaluates
// whether a user (and their groups) satisfy any of those assignments at
// the required permission level. MethodPermission maps the HTTP method
// of an inbound MCP request onto a required permission tier.
//
// All three are pure functions over data the AssignmentRegistry already
// projects — no per-request kubernetes API calls.
package auth

import (
	"net/http"
	"sort"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// EffectiveAssignments returns the union of:
//   - assignments named by explicitRefs (Adapter.Spec.RouteAssignmentRefs)
//   - assignments whose MCPServerRef matches serverRef in namespace
//     (the P2.4i bridge for /api/v1/registry/{serverID}/routes)
//
// Results are deduplicated by ID and sorted for stable iteration. Empty
// serverRef skips the server-scoped lookup; the caller is then operating
// on an adapter that doesn't bind to an MCPServer (e.g. inline
// SidecarConfig only).
func EffectiveAssignments(reg AssignmentRegistry, namespace string, explicitRefs []string, serverRef string) []*RegisteredAssignment {
	if reg == nil {
		return nil
	}
	seen := make(map[string]*RegisteredAssignment)
	for _, name := range explicitRefs {
		if name == "" {
			continue
		}
		id := namespace + "/" + name
		if asg, ok := reg.GetAssignment(id); ok {
			seen[id] = asg
		}
	}
	if serverRef != "" {
		for _, asg := range reg.ListByMCPServerRef(namespace, serverRef) {
			seen[asg.ID] = asg
		}
	}
	out := make([]*RegisteredAssignment, 0, len(seen))
	for _, asg := range seen {
		out = append(out, asg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Allowed reports whether (userID + userGroups) satisfy any of the given
// assignments at or above the required permission level.
//
// Fail-open semantics: when len(assignments) == 0 the function returns
// true. This preserves the pre-P2.5a behavior — adapters with NO
// RouteAssignments accept any authenticated caller. The moment an
// adapter gains even one assignment it switches to fail-closed
// (a matched subject becomes required).
//
// Match rules:
//   - userID matches if it appears in any assignment's Users slice.
//   - A group match occurs when any of userGroups appears in any
//     assignment's Groups slice.
//   - The assignment's Permissions must be >= required, per
//     permissionAtLeast (read < write < admin).
func Allowed(userID string, userGroups []string, assignments []*RegisteredAssignment, required mcpv1alpha1.RouteAssignmentPermission) bool {
	if len(assignments) == 0 {
		return true
	}
	groupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		if g != "" {
			groupSet[g] = struct{}{}
		}
	}
	for _, asg := range assignments {
		if asg == nil {
			continue
		}
		if !permissionAtLeast(asg.Permissions, required) {
			continue
		}
		for _, u := range asg.Users {
			if u == userID && userID != "" {
				return true
			}
		}
		for _, g := range asg.Groups {
			if _, ok := groupSet[g]; ok {
				return true
			}
		}
	}
	return false
}

// MethodPermission maps an HTTP method onto the RouteAssignment
// permission level required to invoke it.
//
// MCP traffic is JSON-RPC over POST, so most calls require "write". GET
// is used for tools/list-style polling against a few read-only routes
// and maps to "read". Unknown methods conservatively require "write".
func MethodPermission(method string) mcpv1alpha1.RouteAssignmentPermission {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return mcpv1alpha1.RouteAssignmentPermissionRead
	default:
		return mcpv1alpha1.RouteAssignmentPermissionWrite
	}
}

// permissionAtLeast reports whether granted satisfies required under
// the read < write < admin ordering. An empty granted is treated as
// read (mirrors RouteAssignmentReconciler's default at
// internal/controllers/routeassignment_controller.go).
func permissionAtLeast(granted, required mcpv1alpha1.RouteAssignmentPermission) bool {
	return permissionRank(granted) >= permissionRank(required)
}

func permissionRank(p mcpv1alpha1.RouteAssignmentPermission) int {
	switch p {
	case mcpv1alpha1.RouteAssignmentPermissionAdmin:
		return 2
	case mcpv1alpha1.RouteAssignmentPermissionWrite:
		return 1
	case mcpv1alpha1.RouteAssignmentPermissionRead, "":
		return 0
	}
	return 0
}
