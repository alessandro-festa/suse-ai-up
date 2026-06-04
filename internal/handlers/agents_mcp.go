/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.5c — Agent hot path at /api/v1/agents/{name}/{protocol-path}.
//
// HandleAgentProtocol:
//   1. Looks up the agent in the in-memory AgentRegistry (no per-request
//      k8s call for the agent metadata or its Spec.Tools projection).
//   2. Lazy-fetches the Agent CR via the informer-cached client only for
//      Spec.ACL (the in-memory store deliberately doesn't carry ACL —
//      see store.go:38-41).
//   3. Enforces RouteAssignment ACL via the same EffectiveAssignments
//      / Allowed helpers used by the adapter and vroute endpoints.
//   4. Resolves the AgentProtocol implementation from the registry by
//      agent.Protocol and dispatches.
//
// Resource-level tool ACL (Spec.Tools[] — which Adapters / VirtualMCPRoutes
// the agent may call) is enforced by the protocol implementation; the
// handler hands it the agent + a dispatcher via InvocationContext.
package handlers

import (
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/services"
	"github.com/SUSE/suse-ai-up/pkg/services/agents"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// AgentHandler serves /api/v1/agents/{name}/{protocol-path}.
type AgentHandler struct {
	crClient           client.Client
	namespace          string
	agentRegistry      agents.AgentRegistry
	protocols          *agents.Registry
	assignmentRegistry authsvc.AssignmentRegistry
	userGroupService   *services.UserGroupService
	dispatcher         agents.MCPDispatcher
}

// NewAgentHandler returns a handler configured for the given dependencies.
// crClient is the controller-runtime client (informer-cached reads, no
// per-request API server hit); namespace is the operator's workload
// namespace; agentRegistry is the reconciler-populated AgentStore;
// protocols is the AgentProtocol registry (typically agents.DefaultRegistry);
// assignmentRegistry + userGroupService are the auth dependencies shared
// with the adapter and vroute endpoints; dispatcher is handed to protocol
// implementations so they can invoke source adapters.
func NewAgentHandler(crClient client.Client, namespace string, agentRegistry agents.AgentRegistry, protocols *agents.Registry, assignmentRegistry authsvc.AssignmentRegistry, userGroupService *services.UserGroupService, dispatcher agents.MCPDispatcher) *AgentHandler {
	return &AgentHandler{
		crClient:           crClient,
		namespace:          namespace,
		agentRegistry:      agentRegistry,
		protocols:          protocols,
		assignmentRegistry: assignmentRegistry,
		userGroupService:   userGroupService,
		dispatcher:         dispatcher,
	}
}

// HasProtocolRegistry reports whether the in-memory AgentRegistry was
// wired at construction. The router uses this to decide whether to
// mount the protocol-dispatch sub-route; CRUD endpoints are mounted
// regardless because they read CRs directly via crClient.
func (h *AgentHandler) HasProtocolRegistry() bool {
	return h != nil && h.agentRegistry != nil
}

// HandleAgentProtocol is the entry point for /api/v1/agents/:name/*protocolPath.
func (h *AgentHandler) HandleAgentProtocol(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	agentName := parts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	registered, ok := h.agentRegistry.GetAgent(h.namespace + "/" + agentName)
	if !ok {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Agent not found"})
		return
	}

	// Lazy CR fetch for Spec.ACL. The store deliberately omits ACL
	// (see store.go:38-41) — fetch is informer-cached, no API hit.
	var cr mcpv1alpha1.Agent
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: agentName}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			// Store had it but CR was deleted between projection and fetch
			// — treat as not-found rather than 500ing.
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Agent CR: " + err.Error()})
		return
	}

	// RouteAssignment ACL. Empty Spec.ACL → fail-open (matches adapter /
	// vroute semantics).
	if h.assignmentRegistry != nil && len(cr.Spec.ACL) > 0 {
		aclNames := make([]string, 0, len(cr.Spec.ACL))
		for _, ref := range cr.Spec.ACL {
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
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions for this agent"})
			return
		}
	}

	protocol, ok := h.protocols.Get(registered.Protocol)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, ErrorResponse{
			Error: "Agent protocol not registered: " + registered.Protocol,
		})
		return
	}

	ic := agents.InvocationContext{
		UserID:     userID,
		Agent:      registered,
		Dispatcher: h.dispatcher,
	}
	protocol.HandleRequest(r.Context(), w, r, ic)
}
