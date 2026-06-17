/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Agent list/CRUD HTTP endpoints backing /api/v1/agents.
//
// Mirrors the adapters_crud.go pattern: write methods project the HTTP
// DTO onto an Agent CR via h.crClient, optionally poll Status.Conditions
// [Ready] for ~5s so the response stays synchronous in the common case,
// and rely on AgentReconciler to materialize any external runtime.
// Mutations are admin-gated via UserGroupService.CanManageGroups → 403,
// matching route_assignment.go; agents/vroutes both carry Spec.ACL and
// can grant tool access, so write authority belongs with group admins.
// Reads stay open, mirroring adapter list/get.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

const (
	agentPollInterval = 250 * time.Millisecond
	agentPollTimeout  = 5 * time.Second

	// agentAnnotationCreatedBy stamps the X-User-ID that originated the
	// Create so the read projection can recover owner identity for CRs
	// that round-trip through the HTTP API. CRs created via kubectl
	// simply lack this annotation and project createdBy="".
	agentAnnotationCreatedBy = "suse-ai-up.suse.com/created-by"
)

// AgentToolDTO is the HTTP-facing shape for one entry of Spec.Tools.
// Exactly one of AdapterName or VirtualMCPRouteName must be set.
type AgentToolDTO struct {
	AdapterName        string `json:"adapterName,omitempty"`
	VirtualMCPRouteName string `json:"virtualMCPRouteName,omitempty"`
}

// KeySelectorDTO is the HTTP-facing shape for a Kubernetes key selector
// (either SecretKeySelector or ConfigMapKeySelector).
type KeySelectorDTO struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// EnvVarSourceDTO represents an env var backed by a Secret or ConfigMap.
type EnvVarSourceDTO struct {
	Name            string          `json:"name"`
	SecretKeyRef    *KeySelectorDTO `json:"secretKeyRef,omitempty"`
	ConfigMapKeyRef *KeySelectorDTO `json:"configMapKeyRef,omitempty"`
}

// AgentRuntimeDTO mirrors the writable subset of AgentRuntime. Plain
// key=value env vars use Env; secret/configmap refs use EnvFrom.
type AgentRuntimeDTO struct {
	Image    string            `json:"image,omitempty"`
	Args     []string          `json:"args,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	EnvFrom  []EnvVarSourceDTO `json:"envFrom,omitempty"`
	Port     int32             `json:"port,omitempty"`
	Replicas *int32            `json:"replicas,omitempty"`
}

// AgentResponse is the read projection returned by list/get/create/update.
// Flat shape — no raw k8s metadata; status is rolled up from
// Status.Conditions[Ready] for the simple UI case while Phase carries
// the raw enum for advanced clients.
type AgentResponse struct {
	Name        string           `json:"name"`
	Protocol    string           `json:"protocol"`
	Description string           `json:"description,omitempty"`
	Tools       []AgentToolDTO   `json:"tools"`
	Runtime     *AgentRuntimeDTO `json:"runtime,omitempty"`
	ACL         []string         `json:"acl"`
	Status      string           `json:"status"`
	Phase       string           `json:"phase,omitempty"`
	Mode        string           `json:"mode,omitempty"`
	EndpointURL string           `json:"endpointURL,omitempty"`
	CreatedAt   time.Time        `json:"createdAt"`
	CreatedBy   string           `json:"createdBy,omitempty"`
}

// CreateAgentRequest is the writable subset of AgentSpec accepted by
// POST /api/v1/agents. UpdateAgentRequest is the same shape minus Name
// (which comes from the URL); reuse via embedding keeps the DTOs lean.
type CreateAgentRequest struct {
	Name        string           `json:"name"`
	Protocol    string           `json:"protocol"`
	Description string           `json:"description,omitempty"`
	Tools       []AgentToolDTO   `json:"tools,omitempty"`
	Runtime     *AgentRuntimeDTO `json:"runtime,omitempty"`
	ACL         []string         `json:"acl,omitempty"`
}

// UpdateAgentRequest is what PUT /api/v1/agents/{name} accepts.
// Protocol is immutable post-create (it selects the registered
// AgentProtocol implementation that serves the agent — changing it
// post-hoc would invalidate the in-process registration). Attempts to
// change it are silently dropped, matching adapter ConnectionType.
type UpdateAgentRequest struct {
	Description string           `json:"description,omitempty"`
	Tools       []AgentToolDTO   `json:"tools,omitempty"`
	Runtime     *AgentRuntimeDTO `json:"runtime,omitempty"`
	ACL         []string         `json:"acl,omitempty"`
}

// ListAgents projects every Agent CR in the operator namespace into
// AgentResponse and returns them sorted by name for stable ordering.
// Unauthenticated by handler — reads stay open.
func (h *AgentHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Agent CRUD requires CR mode"})
		return
	}

	var list mcpv1alpha1.AgentList
	if err := h.crClient.List(r.Context(), &list, client.InNamespace(h.namespace)); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to list Agent CRs: " + err.Error()})
		return
	}

	out := make([]AgentResponse, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, agentCRToResponse(&list.Items[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

// GetAgent returns a single Agent by name. 404 on missing.
func (h *AgentHandler) GetAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Agent CRUD requires CR mode"})
		return
	}

	name := agentNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var cr mcpv1alpha1.Agent
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Agent CR: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, agentCRToResponse(&cr))
}

// CreateAgent validates the request, gates on admin permission, projects
// onto an Agent CR, and waits up to ~5s for Ready. Returns 201 with the
// status string ("ready" / "provisioning" / "error") so callers can
// surface the reconciliation outcome without a follow-up GET.
func (h *AgentHandler) CreateAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Agent CRUD requires CR mode"})
		return
	}

	var req CreateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
		return
	}
	if req.Protocol == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "protocol is required"})
		return
	}
	if err := validateAgentTools(req.Tools); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageAgents(r.Context(), userID, w) {
		return
	}

	cr := buildAgentCR(&req, h.namespace, userID)
	if err := h.crClient.Create(r.Context(), cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("Agent %q already exists", req.Name)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create Agent CR: " + err.Error()})
		return
	}

	observed, _ := h.pollAgentReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusCreated, agentCRToResponse(observed))
}

// UpdateAgent mutates writable Spec fields and polls for Ready.
// Spec.Protocol is intentionally not mutated on update (immutable
// post-create — see UpdateAgentRequest comment). Conflicts on Update
// surface as 409 so callers can retry without losing their copy.
func (h *AgentHandler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Agent CRUD requires CR mode"})
		return
	}

	name := agentNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var req UpdateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}
	if err := validateAgentTools(req.Tools); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageAgents(r.Context(), userID, w) {
		return
	}

	var cr mcpv1alpha1.Agent
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Agent CR: " + err.Error()})
		return
	}

	cr.Spec.Description = req.Description
	cr.Spec.Tools = toolDTOsToCR(req.Tools)
	cr.Spec.Runtime = runtimeDTOToCR(req.Runtime)
	cr.Spec.ACL = toLocalObjectRefs(req.ACL)

	if err := h.crClient.Update(r.Context(), &cr); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "Agent was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update Agent CR: " + err.Error()})
		return
	}

	observed, _ := h.pollAgentReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusOK, agentCRToResponse(observed))
}

// DeleteAgent removes the Agent CR; OwnerReferences cascade any owned
// runtime Deployment+Service. 204 on success, 404 on missing.
func (h *AgentHandler) DeleteAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "Agent CRUD requires CR mode"})
		return
	}

	name := agentNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageAgents(r.Context(), userID, w) {
		return
	}

	cr := &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.namespace},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete Agent CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// canManageAgents short-circuits to true when the userGroupService is
// nil so tests can exercise the handler without wiring a UserGroupService.
// Production bootstrap always wires it.
func (h *AgentHandler) canManageAgents(ctx context.Context, userID string, w http.ResponseWriter) bool {
	if h.userGroupService == nil {
		return true
	}
	canManage, err := h.userGroupService.CanManageGroups(ctx, userID)
	if err != nil || !canManage {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions to manage agents"})
		return false
	}
	return true
}

// pollAgentReady waits up to agentPollTimeout for Ready to flip. Returns
// the most recent observed CR + a status string suitable for the
// AgentResponse:
//   - "ready" when Ready=True
//   - "error" when Ready=False with a terminal reason
//   - "provisioning" otherwise (including timeout — caller can poll GET)
func (h *AgentHandler) pollAgentReady(ctx context.Context, name string) (*mcpv1alpha1.Agent, string) {
	deadline := time.Now().Add(agentPollTimeout)
	var latest mcpv1alpha1.Agent
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			if s, ok := agentStatusFromConditions(latest.Status.Conditions); ok {
				return &latest, s
			}
		}
		if time.Now().After(deadline) {
			return &latest, agentStatusProvisioning
		}
		select {
		case <-ctx.Done():
			return &latest, agentStatusProvisioning
		case <-time.After(agentPollInterval):
		}
	}
}

const (
	agentStatusReady        = "ready"
	agentStatusError        = "error"
	agentStatusProvisioning = "provisioning"
)

// agentStatusFromConditions returns ("ready"|"error", true) when the
// Ready condition is in a terminal state, or ("", false) when the
// reconciler is still working. The poll loop translates the false return
// into "provisioning" on timeout / context cancel.
func agentStatusFromConditions(conditions []metav1.Condition) (string, bool) {
	for _, c := range conditions {
		if c.Type != mcpv1alpha1.AgentConditionReady {
			continue
		}
		switch c.Status {
		case metav1.ConditionTrue:
			return agentStatusReady, true
		case metav1.ConditionFalse:
			if isTerminalAgentReason(c.Reason) {
				return agentStatusError, true
			}
		}
	}
	return "", false
}

// isTerminalAgentReason mirrors isTerminalAdapterReason — only reasons
// the controller will not retry should appear here. Anything else is a
// transient state we want to keep polling through.
func isTerminalAgentReason(reason string) bool {
	switch reason {
	case "ProtocolUnknown", "ToolMissing", "InvalidSpec":
		return true
	}
	return false
}

// buildAgentCR projects the HTTP DTO onto a fresh Agent CR. The
// reconciler fills in Status; AgentReconciler stamps OwnerReferences on
// any external runtime Deployment so DeleteAgent cascades cleanly.
func buildAgentCR(req *CreateAgentRequest, namespace, userID string) *mcpv1alpha1.Agent {
	return &mcpv1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Annotations: map[string]string{
				agentAnnotationCreatedBy: userID,
			},
		},
		Spec: mcpv1alpha1.AgentSpec{
			Protocol:    req.Protocol,
			Description: req.Description,
			Tools:       toolDTOsToCR(req.Tools),
			Runtime:     runtimeDTOToCR(req.Runtime),
			ACL:         toLocalObjectRefs(req.ACL),
		},
	}
}

// agentCRToResponse projects an Agent CR onto AgentResponse for the
// HTTP read path. Status fields not yet populated (newly-created CRs
// before the first reconcile) project to their zero values so the UI
// can render without nil-checks.
func agentCRToResponse(cr *mcpv1alpha1.Agent) AgentResponse {
	if cr == nil {
		return AgentResponse{}
	}
	resp := AgentResponse{
		Name:        cr.Name,
		Protocol:    cr.Spec.Protocol,
		Description: cr.Spec.Description,
		Tools:       toolCRToDTOs(cr.Spec.Tools),
		Runtime:     runtimeCRToDTO(cr.Spec.Runtime),
		ACL:         localObjectRefsToNames(cr.Spec.ACL),
		Phase:       string(cr.Status.Phase),
		Mode:        string(cr.Status.Mode),
		EndpointURL: cr.Status.EndpointURL,
		CreatedAt:   cr.CreationTimestamp.Time,
		CreatedBy:   cr.Annotations[agentAnnotationCreatedBy],
	}
	if s, ok := agentStatusFromConditions(cr.Status.Conditions); ok {
		resp.Status = s
	} else {
		resp.Status = agentStatusProvisioning
	}
	return resp
}

// validateAgentTools enforces the AgentToolRef invariant — exactly one
// of adapterName / virtualMCPRouteName must be set per entry. Empty
// list is allowed (the agent has no tool access; see AgentSpec.Tools).
func validateAgentTools(tools []AgentToolDTO) error {
	for i, t := range tools {
		hasAdapter := t.AdapterName != ""
		hasVRoute := t.VirtualMCPRouteName != ""
		if hasAdapter == hasVRoute {
			return fmt.Errorf("tools[%d]: exactly one of adapterName or virtualMCPRouteName must be set", i)
		}
	}
	return nil
}

// toolDTOsToCR / toolCRToDTOs translate between the flat HTTP DTO and
// the CR's LocalObjectReference-wrapped shape.
func toolDTOsToCR(in []AgentToolDTO) []mcpv1alpha1.AgentToolRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]mcpv1alpha1.AgentToolRef, 0, len(in))
	for _, t := range in {
		ref := mcpv1alpha1.AgentToolRef{}
		if t.AdapterName != "" {
			ref.AdapterRef = &corev1.LocalObjectReference{Name: t.AdapterName}
		}
		if t.VirtualMCPRouteName != "" {
			ref.VirtualMCPRouteRef = &corev1.LocalObjectReference{Name: t.VirtualMCPRouteName}
		}
		out = append(out, ref)
	}
	return out
}

func toolCRToDTOs(in []mcpv1alpha1.AgentToolRef) []AgentToolDTO {
	out := make([]AgentToolDTO, 0, len(in))
	for _, t := range in {
		dto := AgentToolDTO{}
		if t.AdapterRef != nil {
			dto.AdapterName = t.AdapterRef.Name
		}
		if t.VirtualMCPRouteRef != nil {
			dto.VirtualMCPRouteName = t.VirtualMCPRouteRef.Name
		}
		out = append(out, dto)
	}
	return out
}

// runtimeDTOToCR / runtimeCRToDTO translate between the HTTP DTO and
// the CR runtime shape. Plain key=value env vars use Env (map); env
// vars backed by Secret/ConfigMap refs use EnvFrom (array of
// EnvVarSourceDTO).
func runtimeDTOToCR(in *AgentRuntimeDTO) *mcpv1alpha1.AgentRuntime {
	if in == nil {
		return nil
	}
	out := &mcpv1alpha1.AgentRuntime{
		Image:    in.Image,
		Args:     in.Args,
		Port:     in.Port,
		Replicas: in.Replicas,
	}
	total := len(in.Env) + len(in.EnvFrom)
	if total > 0 {
		out.Env = make([]corev1.EnvVar, 0, total)
		for k, v := range in.Env {
			out.Env = append(out.Env, corev1.EnvVar{Name: k, Value: v})
		}
		for _, ef := range in.EnvFrom {
			ev := corev1.EnvVar{Name: ef.Name}
			if ef.SecretKeyRef != nil {
				ev.ValueFrom = &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: ef.SecretKeyRef.Name},
						Key:                  ef.SecretKeyRef.Key,
					},
				}
			} else if ef.ConfigMapKeyRef != nil {
				ev.ValueFrom = &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: ef.ConfigMapKeyRef.Name},
						Key:                  ef.ConfigMapKeyRef.Key,
					},
				}
			}
			out.Env = append(out.Env, ev)
		}
		sort.Slice(out.Env, func(i, j int) bool { return out.Env[i].Name < out.Env[j].Name })
	}
	return out
}

func runtimeCRToDTO(in *mcpv1alpha1.AgentRuntime) *AgentRuntimeDTO {
	if in == nil {
		return nil
	}
	out := &AgentRuntimeDTO{
		Image:    in.Image,
		Args:     in.Args,
		Port:     in.Port,
		Replicas: in.Replicas,
	}
	for _, e := range in.Env {
		if e.ValueFrom != nil {
			dto := EnvVarSourceDTO{Name: e.Name}
			if e.ValueFrom.SecretKeyRef != nil {
				dto.SecretKeyRef = &KeySelectorDTO{
					Name: e.ValueFrom.SecretKeyRef.Name,
					Key:  e.ValueFrom.SecretKeyRef.Key,
				}
			} else if e.ValueFrom.ConfigMapKeyRef != nil {
				dto.ConfigMapKeyRef = &KeySelectorDTO{
					Name: e.ValueFrom.ConfigMapKeyRef.Name,
					Key:  e.ValueFrom.ConfigMapKeyRef.Key,
				}
			}
			out.EnvFrom = append(out.EnvFrom, dto)
		} else {
			if out.Env == nil {
				out.Env = make(map[string]string)
			}
			out.Env[e.Name] = e.Value
		}
	}
	return out
}

// toLocalObjectRefs lives in user_group_crud.go — reuse it (same
// signature, same drop-empty semantics).

func localObjectRefsToNames(refs []corev1.LocalObjectReference) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return out
}

// agentNameFromPath extracts the {name} segment from
// /api/v1/agents/{name} (or any longer prefix like
// /api/v1/agents/{name}/*). Returns "" if the path doesn't start with
// the expected prefix or the name segment is empty.
func agentNameFromPath(p string) string {
	trimmed := strings.TrimPrefix(p, "/api/v1/agents/")
	if trimmed == p {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
