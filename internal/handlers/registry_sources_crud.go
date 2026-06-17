/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// MCPRegistry list/CRUD HTTP endpoints backing /api/v1/registry-sources.
//
// Mirrors agents_crud.go / vroutes_crud.go: write methods project the HTTP
// DTO onto an MCPRegistry CR via h.crClient, poll Status.Conditions[Ready]
// for ~5s so the response stays synchronous in the common case, and rely on
// MCPRegistryReconciler to fetch the source and create child MCPServer CRs.
// Mutations are admin-gated (UserGroupService.CanManageGroups -> 403) because
// registries control which MCP servers are available to the entire namespace.
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
	"github.com/SUSE/suse-ai-up/pkg/services"
)

const (
	registryPollInterval = 250 * time.Millisecond
	registryPollTimeout  = 5 * time.Second

	registryAnnotationCreatedBy = "suse-ai-up.suse.com/created-by"
)

// RegistrySourceHandler serves /api/v1/registry-sources CRUD endpoints.
type RegistrySourceHandler struct {
	crClient         client.Client
	namespace        string
	userGroupService *services.UserGroupService
}

// NewRegistrySourceHandler returns a handler configured for the given
// dependencies. crClient is the controller-runtime client (informer-cached
// reads); namespace is the operator's workload namespace.
func NewRegistrySourceHandler(crClient client.Client, namespace string, ugs *services.UserGroupService) *RegistrySourceHandler {
	return &RegistrySourceHandler{
		crClient:         crClient,
		namespace:        namespace,
		userGroupService: ugs,
	}
}

// CreateRegistrySourceRequest is the writable subset of MCPRegistrySpec
// accepted by POST /api/v1/registry-sources.
type CreateRegistrySourceRequest struct {
	Name            string `json:"name"`
	Format          string `json:"format,omitempty"`
	URL             string `json:"url,omitempty"`
	ConfigMapRef    string `json:"configMapRef,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	RefreshInterval string `json:"refreshInterval,omitempty"` // e.g. "5m", "1h"
}

// RegistrySourceResponse is the read projection returned by list/get/create/update.
type RegistrySourceResponse struct {
	Name            string `json:"name"`
	Format          string `json:"format,omitempty"`
	URL             string `json:"url,omitempty"`
	ConfigMapRef    string `json:"configMapRef,omitempty"`
	Priority        int32  `json:"priority"`
	RefreshInterval string `json:"refreshInterval,omitempty"`
	Phase           string `json:"phase,omitempty"`
	LastSyncTime    string `json:"lastSyncTime,omitempty"`
	ServerCount     int32  `json:"serverCount"`
	SyncError       string `json:"syncError,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
}

// WellKnownRegistrySource represents a pre-defined registry source that
// users can pick from the UI.
type WellKnownRegistrySource struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Format      string `json:"format"`
	Icon        string `json:"icon,omitempty"`
}

// ListRegistrySources projects every MCPRegistry CR in the operator
// namespace into RegistrySourceResponse and returns them sorted by name
// for stable ordering. Unauthenticated by handler -- reads stay open.
func (h *RegistrySourceHandler) ListRegistrySources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "RegistrySource CRUD requires CR mode"})
		return
	}

	var list mcpv1alpha1.MCPRegistryList
	if err := h.crClient.List(r.Context(), &list, client.InNamespace(h.namespace)); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to list MCPRegistry CRs: " + err.Error()})
		return
	}

	out := make([]RegistrySourceResponse, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, registryCRToResponse(&list.Items[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

// GetRegistrySource returns a single MCPRegistry by name. 404 on missing.
func (h *RegistrySourceHandler) GetRegistrySource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "RegistrySource CRUD requires CR mode"})
		return
	}

	name := registrySourceNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var cr mcpv1alpha1.MCPRegistry
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Registry source not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch MCPRegistry CR: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, registryCRToResponse(&cr))
}

// CreateRegistrySource validates the request, gates on admin permission,
// projects onto an MCPRegistry CR, and waits up to ~5s for Ready. Returns
// 201 with the projected response so callers can surface the reconciliation
// outcome without a follow-up GET.
func (h *RegistrySourceHandler) CreateRegistrySource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "RegistrySource CRUD requires CR mode"})
		return
	}

	var req CreateRegistrySourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
		return
	}
	hasURL := req.URL != ""
	hasConfigMap := req.ConfigMapRef != ""
	if hasURL == hasConfigMap {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "exactly one of url or configMapRef must be set"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageRegistrySources(r.Context(), userID, w) {
		return
	}

	cr, err := buildRegistryCR(&req, h.namespace, userID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	if err := h.crClient.Create(r.Context(), cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("Registry source %q already exists", req.Name)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create MCPRegistry CR: " + err.Error()})
		return
	}

	observed, _ := h.pollRegistryReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusCreated, registryCRToResponse(observed))
}

// UpdateRegistrySource fetches the existing MCPRegistry, updates mutable
// Spec fields (Format, URL, ConfigMapRef, Priority, RefreshInterval), and
// polls for Ready. Conflicts on Update surface as 409 so callers can retry.
func (h *RegistrySourceHandler) UpdateRegistrySource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "RegistrySource CRUD requires CR mode"})
		return
	}

	name := registrySourceNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var req CreateRegistrySourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageRegistrySources(r.Context(), userID, w) {
		return
	}

	var cr mcpv1alpha1.MCPRegistry
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Registry source not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch MCPRegistry CR: " + err.Error()})
		return
	}

	// Update mutable Spec fields.
	cr.Spec.Format = req.Format
	cr.Spec.Priority = req.Priority
	cr.Spec.Source.URL = req.URL
	if req.ConfigMapRef != "" {
		cr.Spec.Source.ConfigMapRef = &corev1.LocalObjectReference{Name: req.ConfigMapRef}
	} else {
		cr.Spec.Source.ConfigMapRef = nil
	}
	if req.RefreshInterval != "" {
		d, err := time.ParseDuration(req.RefreshInterval)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid refreshInterval: " + err.Error()})
			return
		}
		cr.Spec.RefreshInterval = &metav1.Duration{Duration: d}
	} else {
		cr.Spec.RefreshInterval = nil
	}

	if err := h.crClient.Update(r.Context(), &cr); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "Registry source was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update MCPRegistry CR: " + err.Error()})
		return
	}

	observed, _ := h.pollRegistryReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusOK, registryCRToResponse(observed))
}

// DeleteRegistrySource removes the MCPRegistry CR. OwnerReferences on
// child MCPServer CRs cascade the delete. 204 on success, 404 on missing.
func (h *RegistrySourceHandler) DeleteRegistrySource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "RegistrySource CRUD requires CR mode"})
		return
	}

	name := registrySourceNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageRegistrySources(r.Context(), userID, w) {
		return
	}

	cr := &mcpv1alpha1.MCPRegistry{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.namespace},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Registry source not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete MCPRegistry CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetWellKnownRegistrySources returns a static list of well-known registry
// sources that users can pick from. No authentication required.
func (h *RegistrySourceHandler) GetWellKnownRegistrySources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wellKnown := []WellKnownRegistrySource{
		{
			Name:        "mcp-official",
			DisplayName: "Official MCP Registry",
			Description: "The official Model Context Protocol server registry at registry.modelcontextprotocol.io",
			URL:         "https://registry.modelcontextprotocol.io/v0.1/servers",
			Format:      "mcp-registry-v0.1",
			Icon:        "https://modelcontextprotocol.io/favicon.ico",
		},
	}
	writeJSON(w, http.StatusOK, wellKnown)
}

// canManageRegistrySources short-circuits to true when userGroupService is
// nil so tests can exercise the handler without wiring a UserGroupService.
// Production bootstrap always wires it.
func (h *RegistrySourceHandler) canManageRegistrySources(ctx context.Context, userID string, w http.ResponseWriter) bool {
	if h.userGroupService == nil {
		return true
	}
	canManage, err := h.userGroupService.CanManageGroups(ctx, userID)
	if err != nil || !canManage {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions to manage registry sources"})
		return false
	}
	return true
}

// pollRegistryReady waits up to registryPollTimeout for Ready to flip.
// Returns the most recent observed CR and a status string.
func (h *RegistrySourceHandler) pollRegistryReady(ctx context.Context, name string) (*mcpv1alpha1.MCPRegistry, string) {
	deadline := time.Now().Add(registryPollTimeout)
	var latest mcpv1alpha1.MCPRegistry
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			if s, ok := registryStatusFromConditions(latest.Status.Conditions); ok {
				return &latest, s
			}
		}
		if time.Now().After(deadline) {
			return &latest, registryStatusProvisioning
		}
		select {
		case <-ctx.Done():
			return &latest, registryStatusProvisioning
		case <-time.After(registryPollInterval):
		}
	}
}

const (
	registryStatusReady        = "ready"
	registryStatusError        = "error"
	registryStatusProvisioning = "provisioning"
)

func registryStatusFromConditions(conditions []metav1.Condition) (string, bool) {
	for _, c := range conditions {
		if c.Type != mcpv1alpha1.MCPRegistryConditionReady {
			continue
		}
		switch c.Status {
		case metav1.ConditionTrue:
			return registryStatusReady, true
		case metav1.ConditionFalse:
			if isTerminalRegistryReason(c.Reason) {
				return registryStatusError, true
			}
		}
	}
	return "", false
}

// isTerminalRegistryReason -- reasons the controller will not retry. Parse
// failures and invalid sources are terminal; transient fetch errors are not.
func isTerminalRegistryReason(reason string) bool {
	switch reason {
	case "InvalidSource", "ParseFailed", "InvalidSpec":
		return true
	}
	return false
}

// buildRegistryCR projects the HTTP DTO onto a fresh MCPRegistry CR.
func buildRegistryCR(req *CreateRegistrySourceRequest, namespace, userID string) (*mcpv1alpha1.MCPRegistry, error) {
	priority := req.Priority
	if priority == 0 {
		priority = 100
	}

	cr := &mcpv1alpha1.MCPRegistry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Annotations: map[string]string{
				registryAnnotationCreatedBy: userID,
			},
		},
		Spec: mcpv1alpha1.MCPRegistrySpec{
			Format:   req.Format,
			Priority: priority,
			Source: mcpv1alpha1.MCPRegistrySource{
				URL: req.URL,
			},
		},
	}

	if req.ConfigMapRef != "" {
		cr.Spec.Source.ConfigMapRef = &corev1.LocalObjectReference{Name: req.ConfigMapRef}
	}

	if req.RefreshInterval != "" {
		d, err := time.ParseDuration(req.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid refreshInterval: %w", err)
		}
		cr.Spec.RefreshInterval = &metav1.Duration{Duration: d}
	}

	return cr, nil
}

// registryCRToResponse projects an MCPRegistry CR onto RegistrySourceResponse
// for the HTTP read path. Status fields not yet populated (newly-created CRs
// before the first reconcile) project to their zero values so the UI can
// render without nil-checks.
func registryCRToResponse(reg *mcpv1alpha1.MCPRegistry) RegistrySourceResponse {
	if reg == nil {
		return RegistrySourceResponse{}
	}

	resp := RegistrySourceResponse{
		Name:        reg.Name,
		Format:      reg.Spec.Format,
		URL:         reg.Spec.Source.URL,
		Priority:    reg.Spec.Priority,
		Phase:       string(reg.Status.Phase),
		ServerCount: reg.Status.ObservedServerCount,
		SyncError:   reg.Status.SyncError,
	}

	if reg.Spec.Source.ConfigMapRef != nil {
		resp.ConfigMapRef = reg.Spec.Source.ConfigMapRef.Name
	}
	if reg.Spec.RefreshInterval != nil {
		resp.RefreshInterval = reg.Spec.RefreshInterval.Duration.String()
	}
	if reg.Status.LastSyncTime != nil {
		resp.LastSyncTime = reg.Status.LastSyncTime.Time.UTC().Format(time.RFC3339)
	}
	if !reg.CreationTimestamp.IsZero() {
		resp.CreatedAt = reg.CreationTimestamp.Time.UTC().Format(time.RFC3339)
	}

	return resp
}

// registrySourceNameFromPath extracts the {name} segment from
// /api/v1/registry-sources/{name}[/...]. Returns "" if the path doesn't
// start with the expected prefix or the name segment is empty.
func registrySourceNameFromPath(p string) string {
	trimmed := strings.TrimPrefix(p, "/api/v1/registry-sources/")
	if trimmed == p {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
