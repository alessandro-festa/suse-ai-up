/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// VirtualMCPRoute list/CRUD HTTP endpoints backing /api/v1/vroutes.
//
// Mirrors agents_crud.go: write methods project the HTTP DTO onto a
// VirtualMCPRoute CR via h.crClient, poll Status.Conditions[Ready] for
// ~5s so the response stays synchronous in the common case, and rely on
// VirtualMCPRouteReconciler to resolve the catalog. Mutations are
// admin-gated (UserGroupService.CanManageGroups → 403) because Spec.ACL
// can grant tool access via the composed route.
//
// The GET ""/list response omits Status.ResolvedEntries (per the CR
// comment "large routes can produce large status payloads — UIs that
// need only a count should read Status.EntryCount instead"); GET
// /:name returns the full payload including resolvedEntries so
// route-detail UIs can render the catalog.
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
	vroutePollInterval = 250 * time.Millisecond
	vroutePollTimeout  = 5 * time.Second

	vrouteAnnotationCreatedBy = "suse-ai-up.suse.com/created-by"
)

// VirtualMCPSelectorDTO is the flat HTTP shape for VirtualMCPSelector.
// Exactly one of All / Names / Prefix / Regex must be set; the handler
// validates this fail-fast (the CRD comment notes the reconciler also
// enforces it but defers CEL validation).
type VirtualMCPSelectorDTO struct {
	All    bool     `json:"all,omitempty"`
	Names  []string `json:"names,omitempty"`
	Prefix string   `json:"prefix,omitempty"`
	Regex  string   `json:"regex,omitempty"`
}

// VirtualMCPSourceRewriteDTO mirrors VirtualMCPSourceRewrite.
type VirtualMCPSourceRewriteDTO struct {
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
}

// VirtualMCPSourceDTO is one Adapter or MCPServer contributing entries.
// Exactly one of AdapterName / MCPServerName must be set. The flat
// {kind: "adapter"|"mcpServer", name: ...} alternative would be more
// compact but matching the CR field shape keeps the DTO trivially
// round-trippable.
type VirtualMCPSourceDTO struct {
	AdapterName   string                      `json:"adapterName,omitempty"`
	MCPServerName string                      `json:"mcpServerName,omitempty"`
	Tools         *VirtualMCPSelectorDTO      `json:"tools,omitempty"`
	Resources     *VirtualMCPSelectorDTO      `json:"resources,omitempty"`
	Prompts       *VirtualMCPSelectorDTO      `json:"prompts,omitempty"`
	Rewrite       *VirtualMCPSourceRewriteDTO `json:"rewrite,omitempty"`
}

// ResolvedEntryDTO mirrors mcpv1alpha1.ResolvedEntry for the list/get
// projection. Kept as a flat struct (rather than embedding the CR type)
// so the JSON shape is stable even if the CR field set evolves.
type ResolvedEntryDTO struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	OriginalName    string `json:"originalName,omitempty"`
	SourceAdapter   string `json:"sourceAdapter,omitempty"`
	SourceMCPServer string `json:"sourceMCPServer,omitempty"`
}

// VirtualMCPRouteResponse is the read projection.
// ResolvedEntries is included only when the get path projects it (list
// path omits it for payload size).
type VirtualMCPRouteResponse struct {
	Name            string                `json:"name"`
	ExposedAs       string                `json:"exposedAs,omitempty"`
	Description     string                `json:"description,omitempty"`
	Sources         []VirtualMCPSourceDTO `json:"sources"`
	ACL             []string              `json:"acl"`
	Status          string                `json:"status"`
	Phase           string                `json:"phase,omitempty"`
	EndpointURL     string                `json:"endpointURL,omitempty"`
	EntryCount      int32                 `json:"entryCount"`
	ResolvedEntries []ResolvedEntryDTO    `json:"resolvedEntries,omitempty"`
	LastResolvedAt  *time.Time            `json:"lastResolvedAt,omitempty"`
	CreatedAt       time.Time             `json:"createdAt"`
	CreatedBy       string                `json:"createdBy,omitempty"`
}

// CreateVirtualMCPRouteRequest is the writable subset of
// VirtualMCPRouteSpec accepted by POST.
type CreateVirtualMCPRouteRequest struct {
	Name        string                `json:"name"`
	ExposedAs   string                `json:"exposedAs,omitempty"`
	Description string                `json:"description,omitempty"`
	Sources     []VirtualMCPSourceDTO `json:"sources"`
	ACL         []string              `json:"acl,omitempty"`
}

// UpdateVirtualMCPRouteRequest is what PUT accepts. ExposedAs mutations
// reshape the public URL — accepted but documented; clients should not
// flip it without coordinating their consumers.
type UpdateVirtualMCPRouteRequest struct {
	ExposedAs   string                `json:"exposedAs,omitempty"`
	Description string                `json:"description,omitempty"`
	Sources     []VirtualMCPSourceDTO `json:"sources"`
	ACL         []string              `json:"acl,omitempty"`
}

// ListVirtualMCPRoutes returns every route in the namespace, sorted by
// name, with resolvedEntries omitted from each item. Reads are open.
func (h *VirtualMCPRouteHandler) ListVirtualMCPRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "VirtualMCPRoute CRUD requires CR mode"})
		return
	}

	var list mcpv1alpha1.VirtualMCPRouteList
	if err := h.crClient.List(r.Context(), &list, client.InNamespace(h.namespace)); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to list VirtualMCPRoute CRs: " + err.Error()})
		return
	}

	out := make([]VirtualMCPRouteResponse, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, virtualMCPRouteCRToResponse(&list.Items[i], false))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

// GetVirtualMCPRoute returns a single route with resolvedEntries
// populated. 404 on missing.
func (h *VirtualMCPRouteHandler) GetVirtualMCPRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "VirtualMCPRoute CRUD requires CR mode"})
		return
	}

	name := vrouteNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var cr mcpv1alpha1.VirtualMCPRoute
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Virtual route not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch VirtualMCPRoute CR: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, virtualMCPRouteCRToResponse(&cr, true))
}

// CreateVirtualMCPRoute validates the request, gates on admin
// permission, projects onto a CR, and polls for Ready.
func (h *VirtualMCPRouteHandler) CreateVirtualMCPRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "VirtualMCPRoute CRUD requires CR mode"})
		return
	}

	var req CreateVirtualMCPRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
		return
	}
	if err := validateVirtualMCPSources(req.Sources); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageVRoutes(r.Context(), userID, w) {
		return
	}

	cr := buildVirtualMCPRouteCR(&req, h.namespace, userID)
	if err := h.crClient.Create(r.Context(), cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("VirtualMCPRoute %q already exists", req.Name)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create VirtualMCPRoute CR: " + err.Error()})
		return
	}

	observed, _ := h.pollVRouteReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusCreated, virtualMCPRouteCRToResponse(observed, true))
}

// UpdateVirtualMCPRoute mutates writable Spec fields and polls for Ready.
func (h *VirtualMCPRouteHandler) UpdateVirtualMCPRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "VirtualMCPRoute CRUD requires CR mode"})
		return
	}

	name := vrouteNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	var req UpdateVirtualMCPRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}
	if err := validateVirtualMCPSources(req.Sources); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageVRoutes(r.Context(), userID, w) {
		return
	}

	var cr mcpv1alpha1.VirtualMCPRoute
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: name}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Virtual route not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch VirtualMCPRoute CR: " + err.Error()})
		return
	}

	cr.Spec.ExposedAs = req.ExposedAs
	cr.Spec.Description = req.Description
	cr.Spec.Sources = sourceDTOsToCR(req.Sources)
	cr.Spec.ACL = toLocalObjectRefs(req.ACL)

	if err := h.crClient.Update(r.Context(), &cr); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "VirtualMCPRoute was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update VirtualMCPRoute CR: " + err.Error()})
		return
	}

	observed, _ := h.pollVRouteReady(r.Context(), cr.Name)
	writeJSON(w, http.StatusOK, virtualMCPRouteCRToResponse(observed, true))
}

// DeleteVirtualMCPRoute removes the route CR. No owned workloads to
// cascade (the reconciler only updates in-process routing tables).
func (h *VirtualMCPRouteHandler) DeleteVirtualMCPRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.crClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "VirtualMCPRoute CRUD requires CR mode"})
		return
	}

	name := vrouteNameFromPath(r.URL.Path)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}
	if !h.canManageVRoutes(r.Context(), userID, w) {
		return
	}

	cr := &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.namespace},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Virtual route not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete VirtualMCPRoute CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// canManageVRoutes short-circuits to true when userGroupService is nil
// so tests can exercise the handler without wiring a UserGroupService.
// Production bootstrap always wires it.
func (h *VirtualMCPRouteHandler) canManageVRoutes(ctx context.Context, userID string, w http.ResponseWriter) bool {
	if h.userGroupService == nil {
		return true
	}
	canManage, err := h.userGroupService.CanManageGroups(ctx, userID)
	if err != nil || !canManage {
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions to manage virtual routes"})
		return false
	}
	return true
}

// pollVRouteReady waits up to vroutePollTimeout for Ready to flip.
func (h *VirtualMCPRouteHandler) pollVRouteReady(ctx context.Context, name string) (*mcpv1alpha1.VirtualMCPRoute, string) {
	deadline := time.Now().Add(vroutePollTimeout)
	var latest mcpv1alpha1.VirtualMCPRoute
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			if s, ok := vrouteStatusFromConditions(latest.Status.Conditions); ok {
				return &latest, s
			}
		}
		if time.Now().After(deadline) {
			return &latest, vrouteStatusProvisioning
		}
		select {
		case <-ctx.Done():
			return &latest, vrouteStatusProvisioning
		case <-time.After(vroutePollInterval):
		}
	}
}

const (
	vrouteStatusReady        = "ready"
	vrouteStatusError        = "error"
	vrouteStatusProvisioning = "provisioning"
)

func vrouteStatusFromConditions(conditions []metav1.Condition) (string, bool) {
	for _, c := range conditions {
		if c.Type != mcpv1alpha1.VirtualMCPRouteConditionReady {
			continue
		}
		switch c.Status {
		case metav1.ConditionTrue:
			return vrouteStatusReady, true
		case metav1.ConditionFalse:
			if isTerminalVRouteReason(c.Reason) {
				return vrouteStatusError, true
			}
		}
	}
	return "", false
}

// isTerminalVRouteReason — reasons the controller will not retry. The
// reconciler reports SourceMissing/Conflict as terminal failure modes
// for resolution; anything else is transient.
func isTerminalVRouteReason(reason string) bool {
	switch reason {
	case "SourceMissing", "Conflict", "InvalidSpec":
		return true
	}
	return false
}

// buildVirtualMCPRouteCR projects the HTTP DTO onto a fresh CR.
func buildVirtualMCPRouteCR(req *CreateVirtualMCPRouteRequest, namespace, userID string) *mcpv1alpha1.VirtualMCPRoute {
	return &mcpv1alpha1.VirtualMCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Annotations: map[string]string{
				vrouteAnnotationCreatedBy: userID,
			},
		},
		Spec: mcpv1alpha1.VirtualMCPRouteSpec{
			ExposedAs:   req.ExposedAs,
			Description: req.Description,
			Sources:     sourceDTOsToCR(req.Sources),
			ACL:         toLocalObjectRefs(req.ACL),
		},
	}
}

// virtualMCPRouteCRToResponse projects a CR onto the response DTO.
// includeResolved=true populates ResolvedEntries; the list path passes
// false to keep the payload small.
func virtualMCPRouteCRToResponse(cr *mcpv1alpha1.VirtualMCPRoute, includeResolved bool) VirtualMCPRouteResponse {
	if cr == nil {
		return VirtualMCPRouteResponse{}
	}
	resp := VirtualMCPRouteResponse{
		Name:        cr.Name,
		ExposedAs:   cr.Spec.ExposedAs,
		Description: cr.Spec.Description,
		Sources:     sourceCRToDTOs(cr.Spec.Sources),
		ACL:         localObjectRefsToNames(cr.Spec.ACL),
		Phase:       string(cr.Status.Phase),
		EndpointURL: cr.Status.EndpointURL,
		EntryCount:  cr.Status.EntryCount,
		CreatedAt:   cr.CreationTimestamp.Time,
		CreatedBy:   cr.Annotations[vrouteAnnotationCreatedBy],
	}
	if cr.Status.LastResolvedTime != nil {
		t := cr.Status.LastResolvedTime.Time
		resp.LastResolvedAt = &t
	}
	if s, ok := vrouteStatusFromConditions(cr.Status.Conditions); ok {
		resp.Status = s
	} else {
		resp.Status = vrouteStatusProvisioning
	}
	if includeResolved {
		resp.ResolvedEntries = resolvedEntriesCRToDTOs(cr.Status.ResolvedEntries)
	}
	return resp
}

// validateVirtualMCPSources enforces: at least one source; each source
// has exactly one of AdapterName/MCPServerName; each selector has at
// most one of all/names/prefix/regex (the reconciler also enforces this
// but failing fast here gives the UI a clean 400 before the CR is
// created).
func validateVirtualMCPSources(sources []VirtualMCPSourceDTO) error {
	if len(sources) == 0 {
		return fmt.Errorf("sources must contain at least one entry")
	}
	for i, s := range sources {
		hasAdapter := s.AdapterName != ""
		hasMCPServer := s.MCPServerName != ""
		if hasAdapter == hasMCPServer {
			return fmt.Errorf("sources[%d]: exactly one of adapterName or mcpServerName must be set", i)
		}
		for _, pair := range []struct {
			label string
			sel   *VirtualMCPSelectorDTO
		}{
			{"tools", s.Tools},
			{"resources", s.Resources},
			{"prompts", s.Prompts},
		} {
			if err := validateVirtualMCPSelector(pair.sel); err != nil {
				return fmt.Errorf("sources[%d].%s: %w", i, pair.label, err)
			}
		}
	}
	return nil
}

// validateVirtualMCPSelector enforces "at most one of all/names/prefix/
// regex". nil selector is allowed (means "don't pick anything of this
// kind"); the empty selector (all four fields zero) is also allowed —
// it's a no-op the reconciler skips.
func validateVirtualMCPSelector(s *VirtualMCPSelectorDTO) error {
	if s == nil {
		return nil
	}
	set := 0
	if s.All {
		set++
	}
	if len(s.Names) > 0 {
		set++
	}
	if s.Prefix != "" {
		set++
	}
	if s.Regex != "" {
		set++
	}
	if set > 1 {
		return fmt.Errorf("at most one of all/names/prefix/regex may be set")
	}
	return nil
}

// sourceDTOsToCR / sourceCRToDTOs translate between flat HTTP DTOs and
// the CR's LocalObjectReference-wrapped shape.
func sourceDTOsToCR(in []VirtualMCPSourceDTO) []mcpv1alpha1.VirtualMCPSource {
	out := make([]mcpv1alpha1.VirtualMCPSource, 0, len(in))
	for _, s := range in {
		src := mcpv1alpha1.VirtualMCPSource{
			Tools:     selectorDTOToCR(s.Tools),
			Resources: selectorDTOToCR(s.Resources),
			Prompts:   selectorDTOToCR(s.Prompts),
			Rewrite:   rewriteDTOToCR(s.Rewrite),
		}
		if s.AdapterName != "" {
			src.AdapterRef = &corev1.LocalObjectReference{Name: s.AdapterName}
		}
		if s.MCPServerName != "" {
			src.MCPServerRef = &corev1.LocalObjectReference{Name: s.MCPServerName}
		}
		out = append(out, src)
	}
	return out
}

func sourceCRToDTOs(in []mcpv1alpha1.VirtualMCPSource) []VirtualMCPSourceDTO {
	out := make([]VirtualMCPSourceDTO, 0, len(in))
	for _, s := range in {
		dto := VirtualMCPSourceDTO{
			Tools:     selectorCRToDTO(s.Tools),
			Resources: selectorCRToDTO(s.Resources),
			Prompts:   selectorCRToDTO(s.Prompts),
			Rewrite:   rewriteCRToDTO(s.Rewrite),
		}
		if s.AdapterRef != nil {
			dto.AdapterName = s.AdapterRef.Name
		}
		if s.MCPServerRef != nil {
			dto.MCPServerName = s.MCPServerRef.Name
		}
		out = append(out, dto)
	}
	return out
}

func selectorDTOToCR(in *VirtualMCPSelectorDTO) *mcpv1alpha1.VirtualMCPSelector {
	if in == nil {
		return nil
	}
	return &mcpv1alpha1.VirtualMCPSelector{
		All:    in.All,
		Names:  in.Names,
		Prefix: in.Prefix,
		Regex:  in.Regex,
	}
}

func selectorCRToDTO(in *mcpv1alpha1.VirtualMCPSelector) *VirtualMCPSelectorDTO {
	if in == nil {
		return nil
	}
	return &VirtualMCPSelectorDTO{
		All:    in.All,
		Names:  in.Names,
		Prefix: in.Prefix,
		Regex:  in.Regex,
	}
}

func rewriteDTOToCR(in *VirtualMCPSourceRewriteDTO) *mcpv1alpha1.VirtualMCPSourceRewrite {
	if in == nil {
		return nil
	}
	return &mcpv1alpha1.VirtualMCPSourceRewrite{Prefix: in.Prefix, Suffix: in.Suffix}
}

func rewriteCRToDTO(in *mcpv1alpha1.VirtualMCPSourceRewrite) *VirtualMCPSourceRewriteDTO {
	if in == nil {
		return nil
	}
	return &VirtualMCPSourceRewriteDTO{Prefix: in.Prefix, Suffix: in.Suffix}
}

func resolvedEntriesCRToDTOs(in []mcpv1alpha1.ResolvedEntry) []ResolvedEntryDTO {
	out := make([]ResolvedEntryDTO, 0, len(in))
	for _, e := range in {
		out = append(out, ResolvedEntryDTO{
			Name:            e.Name,
			Kind:            string(e.Kind),
			OriginalName:    e.OriginalName,
			SourceAdapter:   e.SourceAdapter,
			SourceMCPServer: e.SourceMCPServer,
		})
	}
	return out
}

// vrouteNameFromPath extracts {name} from /api/v1/vroutes/{name}[/...].
func vrouteNameFromPath(p string) string {
	trimmed := strings.TrimPrefix(p, "/api/v1/vroutes/")
	if trimmed == p {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
