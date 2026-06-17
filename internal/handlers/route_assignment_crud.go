/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4i CR-backed write path for /api/v1/registry/{serverID}/routes.
// Mirrors the layout of adapters_crud.go / user_group_crud.go: the legacy
// handlers in route_assignment.go branch here on h.crClient != nil, and
// these helpers project the HTTP DTOs onto RouteAssignment CRs carrying
// Spec.MCPServerRef={Name: serverID} so the reconciler / proxy hot path
// treat them as server-scoped assignments (Option 3 from #67).
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

const (
	// routeAssignmentAnnotationCreatedBy stamps the X-User-ID that
	// originated the Create, so audit + later read projections can
	// recover owner identity even when the CR was applied via kubectl.
	routeAssignmentAnnotationCreatedBy = "suse-ai-up.suse.com/created-by"
)

// createRouteAssignmentCR is the CR-backed write path for POST. It
// projects req into a RouteAssignment CR with Spec.MCPServerRef.Name set
// to serverID, creates it, and returns the same models.RouteAssignment
// DTO shape the legacy path produces.
func (h *RouteAssignmentHandler) createRouteAssignmentCR(w http.ResponseWriter, r *http.Request, req *CreateRouteAssignmentRequest, serverID, userID string) {
	ctx := r.Context()

	if !h.mcpServerExists(ctx, serverID) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Server not found"})
		return
	}

	name := generateRouteAssignmentID(serverID)
	cr := &mcpv1alpha1.RouteAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: h.namespace,
			Annotations: map[string]string{
				routeAssignmentAnnotationCreatedBy: userID,
			},
		},
		Spec: mcpv1alpha1.RouteAssignmentSpec{
			Users:        toLocalObjectRefs(req.UserIDs),
			Groups:       toLocalObjectRefs(req.GroupIDs),
			Permissions:  mcpv1alpha1.RouteAssignmentPermission(req.Permissions),
			AutoSpawn:    req.AutoSpawn,
			MCPServerRef: &corev1.LocalObjectReference{Name: serverID},
		},
	}

	if err := h.crClient.Create(ctx, cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("RouteAssignment %q already exists", name)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create RouteAssignment CR: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, routeAssignmentCRToModel(cr, serverID))
}

// listRouteAssignmentCRs is the CR-backed read path for GET. Lists all
// RouteAssignment CRs in the namespace and filters in memory by
// Spec.MCPServerRef.Name == serverID. In-memory filter mirrors what
// other _crud handlers do for similar narrow queries; a field indexer
// would be premature at this scale.
func (h *RouteAssignmentHandler) listRouteAssignmentCRs(w http.ResponseWriter, r *http.Request, serverID string) {
	ctx := r.Context()

	if !h.mcpServerExists(ctx, serverID) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Server not found"})
		return
	}

	out, err := h.listAssignmentsForServer(ctx, serverID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to list RouteAssignment CRs: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// updateRouteAssignmentCR is the CR-backed write path for PUT. Mutates
// the CR's mutable Spec fields and returns the full assignment list for
// the server, matching the legacy contract (the legacy handler also
// returned the whole server.RouteAssignments slice on Update).
func (h *RouteAssignmentHandler) updateRouteAssignmentCR(w http.ResponseWriter, r *http.Request, serverID, assignmentID string, req *CreateRouteAssignmentRequest) {
	ctx := r.Context()

	var cr mcpv1alpha1.RouteAssignment
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: assignmentID}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Route assignment not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch RouteAssignment CR: " + err.Error()})
		return
	}
	if cr.Spec.MCPServerRef == nil || cr.Spec.MCPServerRef.Name != serverID {
		// Treat a cross-server assignment lookup as not-found rather than
		// leak the existence of an assignment owned by a different server.
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Route assignment not found"})
		return
	}

	cr.Spec.Users = toLocalObjectRefs(req.UserIDs)
	cr.Spec.Groups = toLocalObjectRefs(req.GroupIDs)
	cr.Spec.Permissions = mcpv1alpha1.RouteAssignmentPermission(req.Permissions)
	cr.Spec.AutoSpawn = req.AutoSpawn

	if err := h.crClient.Update(ctx, &cr); err != nil {
		if apierrors.IsConflict(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "RouteAssignment was modified concurrently; retry"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update RouteAssignment CR: " + err.Error()})
		return
	}

	out, err := h.listAssignmentsForServer(ctx, serverID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to list RouteAssignment CRs: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteRouteAssignmentCR is the CR-backed write path for DELETE. Verifies
// the CR is owned by serverID before deleting so a cross-server delete
// returns 404 rather than silently removing the wrong assignment.
func (h *RouteAssignmentHandler) deleteRouteAssignmentCR(w http.ResponseWriter, r *http.Request, serverID, assignmentID string) {
	ctx := r.Context()

	var cr mcpv1alpha1.RouteAssignment
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: assignmentID}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Route assignment not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch RouteAssignment CR: " + err.Error()})
		return
	}
	if cr.Spec.MCPServerRef == nil || cr.Spec.MCPServerRef.Name != serverID {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Route assignment not found"})
		return
	}

	if err := h.crClient.Delete(ctx, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Route assignment not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete RouteAssignment CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mcpServerExists reports whether an MCPServer CR named serverID exists
// in h.namespace. Mirrors the legacy 404-on-missing-server semantic.
// A nil crClient is impossible here — callers branch on it upstream.
func (h *RouteAssignmentHandler) mcpServerExists(ctx context.Context, serverID string) bool {
	var srv mcpv1alpha1.MCPServer
	err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: serverID}, &srv)
	return err == nil
}

// listAllRouteAssignmentCRs returns every RouteAssignment CR in the
// namespace, regardless of which server owns it.
func (h *RouteAssignmentHandler) listAllRouteAssignmentCRs(w http.ResponseWriter, r *http.Request) {
	var list mcpv1alpha1.RouteAssignmentList
	if err := h.crClient.List(r.Context(), &list, client.InNamespace(h.namespace)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to list route assignments: " + err.Error()})
		return
	}
	out := make([]models.RouteAssignment, 0, len(list.Items))
	for i := range list.Items {
		cr := &list.Items[i]
		serverID := ""
		if cr.Spec.MCPServerRef != nil {
			serverID = cr.Spec.MCPServerRef.Name
		}
		out = append(out, routeAssignmentCRToModel(cr, serverID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// listAssignmentsForServer returns the JSON-ready slice of
// models.RouteAssignment values owned by serverID, sorted by name for a
// stable response order.
func (h *RouteAssignmentHandler) listAssignmentsForServer(ctx context.Context, serverID string) ([]models.RouteAssignment, error) {
	var list mcpv1alpha1.RouteAssignmentList
	if err := h.crClient.List(ctx, &list, client.InNamespace(h.namespace)); err != nil {
		return nil, err
	}
	out := make([]models.RouteAssignment, 0)
	for i := range list.Items {
		cr := &list.Items[i]
		if cr.Spec.MCPServerRef == nil || cr.Spec.MCPServerRef.Name != serverID {
			continue
		}
		out = append(out, routeAssignmentCRToModel(cr, serverID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// routeAssignmentCRToModel projects a RouteAssignment CR onto the
// models.RouteAssignment DTO. serverID is passed in (rather than read
// from Spec.MCPServerRef) so the projection is robust against callers
// that hand us a stripped CR.
func routeAssignmentCRToModel(cr *mcpv1alpha1.RouteAssignment, serverID string) models.RouteAssignment {
	users := make([]string, 0, len(cr.Spec.Users))
	for _, ref := range cr.Spec.Users {
		if ref.Name != "" {
			users = append(users, ref.Name)
		}
	}
	groups := make([]string, 0, len(cr.Spec.Groups))
	for _, ref := range cr.Spec.Groups {
		if ref.Name != "" {
			groups = append(groups, ref.Name)
		}
	}
	return models.RouteAssignment{
		ID:          cr.Name,
		ServerID:    serverID,
		UserIDs:     users,
		GroupIDs:    groups,
		AutoSpawn:   cr.Spec.AutoSpawn,
		Permissions: string(cr.Spec.Permissions),
		CreatedAt:   cr.CreationTimestamp.Time,
		UpdatedAt:   cr.CreationTimestamp.Time,
	}
}

