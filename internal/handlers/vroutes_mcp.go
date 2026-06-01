/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5b — VirtualMCPRoute hot path at /api/v1/vroutes/{name}/mcp.
//
// HandleVirtualMCPProtocol enforces the route's RouteAssignment ACL,
// then decodes the inbound JSON-RPC envelope and branches:
//   - tools/list: build the aggregate catalog from
//     Status.ResolvedEntries (zero per-request k8s calls — Status is
//     read from the informer cache via crClient.Get).
//   - tools/call: reverse-resolve the requested tool name to its origin
//     adapter + pre-rewrite name, rewrite params.name in the body,
//     hand off to MCPDispatcher (= *AdapterHandler.ProxyMCPToAdapter)
//     to invoke the source.
//   - other methods: JSON-RPC "Method not supported on virtual route".
//
// Resources/prompts and MCPServer-source dispatch are explicit
// follow-ups (see PR body); tools + AdapterRef-source is the MVP.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/services"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// MCPDispatcher is the narrow interface VirtualMCPRouteHandler depends
// on for tools/call dispatch. *AdapterHandler satisfies it. Defining
// the interface here (rather than in the adapters_mcp.go package
// proper) keeps the dependency direction one-way and makes the handler
// test stub trivial.
type MCPDispatcher interface {
	ProxyMCPToAdapter(ctx context.Context, adapterID, userID string, body []byte, headers http.Header) (int, string, []byte, error)
}

// VirtualMCPRouteHandler serves /api/v1/vroutes/{name}/mcp.
type VirtualMCPRouteHandler struct {
	crClient           client.Client
	namespace          string
	assignmentRegistry authsvc.AssignmentRegistry
	userGroupService   *services.UserGroupService
	dispatcher         MCPDispatcher
}

// NewVirtualMCPRouteHandler returns a handler configured for the given
// dependencies. crClient is the controller-runtime client (informer-cached
// reads — no per-request API server hit); namespace is the operator's
// workload namespace; assignmentRegistry is the same one the adapter
// hot path uses; userGroupService is the read side of users/groups for
// subject expansion; dispatcher is the MCP dispatcher used by
// tools/call (in production this is *AdapterHandler).
func NewVirtualMCPRouteHandler(crClient client.Client, namespace string, assignmentRegistry authsvc.AssignmentRegistry, userGroupService *services.UserGroupService, dispatcher MCPDispatcher) *VirtualMCPRouteHandler {
	return &VirtualMCPRouteHandler{
		crClient:           crClient,
		namespace:          namespace,
		assignmentRegistry: assignmentRegistry,
		userGroupService:   userGroupService,
		dispatcher:         dispatcher,
	}
}

// HandleVirtualMCPProtocol is the entry point for /api/v1/vroutes/:name/mcp.
func (h *VirtualMCPRouteHandler) HandleVirtualMCPProtocol(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/vroutes/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "mcp" {
		http.NotFound(w, r)
		return
	}
	routeName := parts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	var route mcpv1alpha1.VirtualMCPRoute
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: routeName}, &route); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Virtual route not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch VirtualMCPRoute: " + err.Error()})
		return
	}

	// ACL: empty Spec.ACL → fail-open (matches the P2.5a adapter semantics).
	if h.assignmentRegistry != nil && len(route.Spec.ACL) > 0 {
		aclNames := make([]string, 0, len(route.Spec.ACL))
		for _, ref := range route.Spec.ACL {
			if ref.Name != "" {
				aclNames = append(aclNames, ref.Name)
			}
		}
		asgs := authsvc.EffectiveAssignments(h.assignmentRegistry, h.namespace, aclNames, "")
		required := authsvc.MethodPermission(r.Method)
		var userGroups []string
		if h.userGroupService != nil {
			if u, err := h.userGroupService.GetUser(r.Context(), userID); err == nil && u != nil {
				userGroups = u.Groups
			}
		}
		if !authsvc.Allowed(userID, userGroups, asgs, required) {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions for this virtual route"})
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Failed to read request body: " + err.Error()})
		return
	}

	var envelope mcpEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON-RPC envelope: " + err.Error()})
		return
	}

	switch envelope.Method {
	case "tools/list":
		h.handleToolsList(w, &route, envelope.ID)
	case "tools/call":
		h.handleToolsCall(w, r.Context(), &route, userID, envelope, body, r.Header)
	default:
		writeJSONRPCError(w, envelope.ID, jsonRPCMethodNotFound, "Method not supported on virtual route: "+envelope.Method)
	}
}

// handleToolsList projects Status.ResolvedEntries (Kind=tool) into a
// JSON-RPC tools/list response. Description and inputSchema are not
// carried on ResolvedEntry today — clients see only the exposed name.
// A small follow-up can plumb richer per-tool metadata once the
// capability provider populates it.
func (h *VirtualMCPRouteHandler) handleToolsList(w http.ResponseWriter, route *mcpv1alpha1.VirtualMCPRoute, id any) {
	tools := make([]map[string]any, 0)
	for _, e := range route.Status.ResolvedEntries {
		if e.Kind != mcpv1alpha1.ResolvedEntryKindTool {
			continue
		}
		tools = append(tools, map[string]any{
			"name":        e.Name,
			"description": "", // not carried on ResolvedEntry yet
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		})
	}
	writeJSONRPCResult(w, id, map[string]any{"tools": tools})
}

// handleToolsCall reverse-resolves the requested tool name to its origin
// adapter + pre-rewrite name, rewrites the body's params.name, and
// dispatches via the configured MCPDispatcher.
//
// MCPServer-source entries are not dispatchable today (the proxy hot
// path only knows how to call Adapters); they return a JSON-RPC error
// so the client sees a clear "wrong source kind for dispatch" signal
// rather than a silent failure.
func (h *VirtualMCPRouteHandler) handleToolsCall(w http.ResponseWriter, ctx context.Context, route *mcpv1alpha1.VirtualMCPRoute, userID string, env mcpEnvelope, originalBody []byte, headers http.Header) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if env.Params == nil {
		writeJSONRPCError(w, env.ID, jsonRPCInvalidParams, "tools/call requires params with a tool name")
		return
	}
	if err := json.Unmarshal(env.Params, &params); err != nil {
		writeJSONRPCError(w, env.ID, jsonRPCInvalidParams, "Invalid tools/call params: "+err.Error())
		return
	}
	if params.Name == "" {
		writeJSONRPCError(w, env.ID, jsonRPCInvalidParams, "tools/call requires params.name")
		return
	}

	entry, ok := findResolvedTool(route, params.Name)
	if !ok {
		writeJSONRPCError(w, env.ID, jsonRPCMethodNotFound, "Tool not found on this virtual route: "+params.Name)
		return
	}
	if entry.SourceAdapter == "" {
		// MCPServer-source entries aren't dispatchable today (no proxy
		// path to an MCPServer that doesn't have a wrapping Adapter).
		writeJSONRPCError(w, env.ID, jsonRPCInternalError, "Tool source is an MCPServer without an Adapter — dispatch not supported (see #29 follow-up)")
		return
	}

	originName := entry.OriginalName
	if originName == "" {
		originName = entry.Name
	}

	rewritten, err := rewriteToolName(originalBody, originName)
	if err != nil {
		writeJSONRPCError(w, env.ID, jsonRPCInternalError, "Failed to rewrite tool name for dispatch: "+err.Error())
		return
	}

	sc, ct, resp, err := h.dispatcher.ProxyMCPToAdapter(ctx, entry.SourceAdapter, userID, rewritten, headers)
	if err != nil {
		writeJSONRPCError(w, env.ID, jsonRPCInternalError, "Origin adapter dispatch failed: "+err.Error())
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(sc)
	_, _ = w.Write(resp)
}

// findResolvedTool returns the first Kind=tool entry whose Name matches
// exposedName. Linear scan — fine for the typical few-dozen-entry
// catalog; a map index would be premature.
func findResolvedTool(route *mcpv1alpha1.VirtualMCPRoute, exposedName string) (mcpv1alpha1.ResolvedEntry, bool) {
	for _, e := range route.Status.ResolvedEntries {
		if e.Kind == mcpv1alpha1.ResolvedEntryKindTool && e.Name == exposedName {
			return e, true
		}
	}
	return mcpv1alpha1.ResolvedEntry{}, false
}

// rewriteToolName decodes the JSON-RPC envelope, replaces params.name
// with originName, and re-encodes. Preserves any unknown fields the
// caller may pass through unchanged (id, jsonrpc, params.arguments,
// extension fields).
func rewriteToolName(body []byte, originName string) ([]byte, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(body, &generic); err != nil {
		return nil, err
	}
	paramsRaw, ok := generic["params"]
	if !ok {
		return nil, errors.New("missing params")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, err
	}
	nameJSON, err := json.Marshal(originName)
	if err != nil {
		return nil, err
	}
	params["name"] = nameJSON
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	generic["params"] = newParams
	return json.Marshal(generic)
}

// mcpEnvelope is the minimal JSON-RPC envelope we need to decode to
// branch on method and to forward ID/params untouched.
type mcpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSON-RPC error codes per the MCP spec / JSON-RPC 2.0.
const (
	jsonRPCInvalidParams  = -32602
	jsonRPCMethodNotFound = -32601
	jsonRPCInternalError  = -32603
)

func writeJSONRPCResult(w http.ResponseWriter, id any, result any) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	// Always 200 — JSON-RPC errors are in-band, not HTTP errors.
	writeJSON(w, http.StatusOK, resp)
}
