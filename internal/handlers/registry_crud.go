/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4g CR-backed write path for /api/v1/registry/upload (single),
// /api/v1/registry/{id} (PUT/DELETE). Mirrors the layout of
// adapters_crud.go / user_group_crud.go: the legacy handlers in
// registry.go / registry_upload.go branch here on h.crClient != nil, and
// these helpers project the HTTP DTO onto an MCPServer CR, patch
// Status.Priority, then poll Status.Conditions[Ready] so the response
// stays synchronous for the common case. MCPServerReconciler owns the
// projection back into Store; this file only writes CRs.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

const (
	// Same ~5s synchronous budget the adapter / user-group paths use.
	// MCPServerReconciler runs in-process, so most Ready flips happen
	// within tens of ms; the budget covers conflict-resolution edge cases
	// where the reconciler queues siblings.
	mcpServerPollInterval = 100 * time.Millisecond
	mcpServerPollTimeout  = 5 * time.Second

	// defaultMCPServerPriority is stamped on Status.Priority for
	// HTTP-uploaded MCPServer CRs when the request omits an explicit
	// priority. Chosen to sit above the typical registry-loaded defaults
	// (0–50) so a manually uploaded entry wins ties; callers can downshift
	// or raise via the optional `priority` DTO field.
	defaultMCPServerPriority int32 = 100

	// mcpServerAnnotationCreatedBy mirrors the adapter pattern — tracks
	// the X-User-ID header so audit can reconstruct who uploaded a CR.
	mcpServerAnnotationCreatedBy = "mcp.suse.com/created-by"

	// mcpServerStatusMetaKey is the key written into models.MCPServer.Meta
	// to surface the CR-mode poll outcome ("active" / "provisioning") to
	// HTTP callers without changing the top-level response shape.
	mcpServerStatusMetaKey = "_status"

	// mcpRegistryKind is matched against OwnerReference.Kind to detect
	// MCPRegistry-owned CRs (which we refuse to mutate via HTTP).
	mcpRegistryKind = "MCPRegistry"

	// mcpPriorityMin / mcpPriorityMax bound the user-controllable
	// Status.Priority range. Picked to leave room for future
	// registry-controlled values without overlapping.
	mcpPriorityMin int32 = 0
	mcpPriorityMax int32 = 1000
)

// createMCPServerCR is the CR-backed write path for
// POST /api/v1/registry/upload. It projects req into an MCPServer CR,
// creates it, stamps Status.Priority (with conflict retries because the
// in-process reconciler can bump RV between our Create and Status Patch),
// polls Ready, and returns the same `models.MCPServer` shape the legacy
// path produces, with an added `_meta._status` key.
func (h *RegistryHandler) createMCPServerCR(c *gin.Context, req *UploadRegistryEntryRequest, userID string) {
	ctx := c.Request.Context()

	priority, ok := resolvePriority(req.Priority)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("priority must be between %d and %d", mcpPriorityMin, mcpPriorityMax),
		})
		return
	}

	cr := mcpServerRequestToCR(req, h.namespace, userID)
	if err := h.crClient.Create(ctx, cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("MCPServer %q already exists", req.ID)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create MCPServer CR: " + err.Error()})
		return
	}

	if err := h.setMCPServerPriorityWithRetry(ctx, cr, priority); err != nil {
		// Don't roll back the CR — Status.Priority defaults to 0 and the
		// reconciler will still treat the entry as Active. Surface the
		// failure so the caller knows priority wasn't applied.
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("MCPServer created but failed to set priority: %v", err),
		})
		return
	}

	_, status := h.pollMCPServerReady(ctx, req.ID)

	response := h.projectedMCPServerResponse(req, status)
	c.JSON(http.StatusCreated, response)
}

// updateMCPServerCR is the CR-backed write path for
// PUT /api/v1/registry/:id. Get → coexistence guard → mutate Spec →
// Update (with retry-on-conflict once) → optionally patch Priority →
// poll Ready.
func (h *RegistryHandler) updateMCPServerCR(c *gin.Context, id string, req *UploadRegistryEntryRequest) {
	ctx := c.Request.Context()

	priority, ok := resolvePriority(req.Priority)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("priority must be between %d and %d", mcpPriorityMin, mcpPriorityMax),
		})
		return
	}

	var cr mcpv1alpha1.MCPServer
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("MCPServer %q not found", id)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get MCPServer CR: " + err.Error()})
		return
	}

	if ownerName, owned := isOwnedByMCPRegistry(&cr); owned {
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("MCPServer %q is owned by MCPRegistry %q; update through the registry source instead", id, ownerName),
		})
		return
	}

	applyMCPServerRequestToCR(req, &cr)

	if err := h.crClient.Update(ctx, &cr); err != nil {
		if apierrors.IsConflict(err) {
			// One re-fetch + retry. Second conflict surfaces as 409 so the
			// caller knows to retry from a fresh GET.
			if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, &cr); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refetch MCPServer CR: " + err.Error()})
				return
			}
			applyMCPServerRequestToCR(req, &cr)
			if err := h.crClient.Update(ctx, &cr); err != nil {
				if apierrors.IsConflict(err) {
					c.JSON(http.StatusConflict, gin.H{"error": "concurrent modification; retry"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update MCPServer CR: " + err.Error()})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update MCPServer CR: " + err.Error()})
			return
		}
	}

	if req.Priority != nil && cr.Status.Priority != priority {
		if err := h.setMCPServerPriorityWithRetry(ctx, &cr, priority); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("MCPServer updated but failed to set priority: %v", err),
			})
			return
		}
	}

	_, status := h.pollMCPServerReady(ctx, id)
	response := h.projectedMCPServerResponse(req, status)
	c.JSON(http.StatusOK, response)
}

// deleteMCPServerCR is the CR-backed write path for
// DELETE /api/v1/registry/:id. Get → coexistence guard → Delete → 204.
// MCPServerReconciler watches the CR and clears the in-process Store on
// its own (removeFromStore in mcpserver_controller.go), so no manual
// store cleanup is needed.
func (h *RegistryHandler) deleteMCPServerCR(c *gin.Context, id string) {
	ctx := c.Request.Context()

	var cr mcpv1alpha1.MCPServer
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("MCPServer %q not found", id)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get MCPServer CR: " + err.Error()})
		return
	}

	if ownerName, owned := isOwnedByMCPRegistry(&cr); owned {
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("MCPServer %q is owned by MCPRegistry %q; delete through the registry source instead", id, ownerName),
		})
		return
	}

	if err := h.crClient.Delete(ctx, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("MCPServer %q not found", id)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete MCPServer CR: " + err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// setMCPServerPriorityWithRetry patches Status.Priority. Uses the caller-
// supplied CR for the first attempt (avoids a cache-Get race where the
// informer cache hasn't observed a just-Created object yet) and only
// refetches on a real RV conflict — the in-process reconciler can bump
// RV via its own Status updates the moment after Create. Bounded retries
// (3 attempts) keep the failure mode predictable.
func (h *RegistryHandler) setMCPServerPriorityWithRetry(ctx context.Context, initial *mcpv1alpha1.MCPServer, priority int32) error {
	const maxAttempts = 3
	var lastErr error
	fresh := initial
	for i := range maxAttempts {
		if fresh.Status.Priority == priority {
			return nil
		}
		original := fresh.DeepCopy()
		fresh.Status.Priority = priority
		err := h.crClient.Status().Patch(ctx, fresh, client.MergeFrom(original))
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		lastErr = err
		if i == maxAttempts-1 {
			break
		}
		var refetched mcpv1alpha1.MCPServer
		if rerr := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: initial.Name}, &refetched); rerr != nil {
			return fmt.Errorf("refetch mcpserver on conflict: %w", rerr)
		}
		fresh = &refetched
	}
	return fmt.Errorf("patch mcpserver status after %d attempts: %w", maxAttempts, lastErr)
}

// pollMCPServerReady waits up to mcpServerPollTimeout for
// MCPServerConditionReady to flip True, returning the latest observed
// CR and a status string suitable for surfacing via Meta["_status"]:
//   - "active" when Ready=True
//   - "provisioning" otherwise (including timeout — the UI will poll GET)
func (h *RegistryHandler) pollMCPServerReady(ctx context.Context, name string) (*mcpv1alpha1.MCPServer, string) {
	deadline := time.Now().Add(mcpServerPollTimeout)
	var latest mcpv1alpha1.MCPServer
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			for _, c := range latest.Status.Conditions {
				if c.Type == mcpv1alpha1.MCPServerConditionReady && c.Status == metav1.ConditionTrue {
					return &latest, "active"
				}
			}
		}
		if time.Now().After(deadline) {
			return &latest, "provisioning"
		}
		select {
		case <-ctx.Done():
			return &latest, "provisioning"
		case <-time.After(mcpServerPollInterval):
		}
	}
}

// isOwnedByMCPRegistry reports whether cr carries an OwnerReference to
// an MCPRegistry. Returns the registry name when true so callers can
// include it in the 409 message.
func isOwnedByMCPRegistry(cr *mcpv1alpha1.MCPServer) (string, bool) {
	for _, ref := range cr.OwnerReferences {
		if ref.Kind == mcpRegistryKind {
			return ref.Name, true
		}
	}
	return "", false
}

// mcpServerRequestToCR projects the HTTP upload DTO into an MCPServer CR
// suitable for Create. Lossy by design — registry-only fields (Tools,
// ValidationStatus, RouteAssignments, AutoSpawn, GitHubConfig) have no
// home in the CR spec yet.
func mcpServerRequestToCR(req *UploadRegistryEntryRequest, namespace, userID string) *mcpv1alpha1.MCPServer {
	cr := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.ID,
			Namespace: namespace,
		},
	}
	if userID != "" {
		cr.Annotations = map[string]string{mcpServerAnnotationCreatedBy: userID}
	}
	applyMCPServerRequestToCR(req, cr)
	return cr
}

// applyMCPServerRequestToCR mutates cr.Spec in place from the request.
// Used by both Create (on a fresh CR) and Update (preserves OwnerRefs,
// status, and any fields the reconciler may have set).
func applyMCPServerRequestToCR(req *UploadRegistryEntryRequest, cr *mcpv1alpha1.MCPServer) {
	cr.Spec.DisplayName = req.Name
	cr.Spec.Description = req.Description
	cr.Spec.Version = req.Version
	cr.Spec.Image = req.Image
	cr.Spec.URL = req.URL

	if req.Repository.URL != "" || req.Repository.Source != "" {
		cr.Spec.Repository = &mcpv1alpha1.MCPServerRepository{
			URL:    req.Repository.URL,
			Source: req.Repository.Source,
		}
	} else {
		cr.Spec.Repository = nil
	}

	if len(req.Packages) > 0 {
		cr.Spec.Packages = make([]mcpv1alpha1.MCPServerPackage, 0, len(req.Packages))
		for _, p := range req.Packages {
			pkg := mcpv1alpha1.MCPServerPackage{
				RegistryType: p.RegistryType,
				Identifier:   p.Identifier,
				Transport:    mcpv1alpha1.MCPServerTransport{Type: p.Transport.Type},
			}
			if len(p.EnvironmentVariables) > 0 {
				pkg.EnvironmentVariables = make([]mcpv1alpha1.MCPServerEnvVar, 0, len(p.EnvironmentVariables))
				for _, ev := range p.EnvironmentVariables {
					pkg.EnvironmentVariables = append(pkg.EnvironmentVariables, mcpv1alpha1.MCPServerEnvVar{
						Name:        ev.Name,
						Description: ev.Description,
						Format:      ev.Format,
						IsSecret:    ev.IsSecret,
						Default:     ev.Default,
					})
				}
			}
			cr.Spec.Packages = append(cr.Spec.Packages, pkg)
		}
	} else {
		cr.Spec.Packages = nil
	}
}

// projectedMCPServerResponse builds the response body for create/update.
// Prefers the reconciler-projected models.MCPServer in Store (so callers
// see the same shape GET returns); falls back to the request payload if
// the poll timed out before the reconciler reflected the CR. Either way,
// stamps `_meta._status` with the poll outcome.
func (h *RegistryHandler) projectedMCPServerResponse(req *UploadRegistryEntryRequest, status string) *models.MCPServer {
	server, err := h.Store.GetMCPServer(req.ID)
	if err != nil || server == nil {
		// Fall back to the request shape. Copy so we don't mutate the
		// caller's request struct.
		fallback := req.MCPServer
		if fallback.Meta == nil {
			fallback.Meta = map[string]interface{}{}
		}
		fallback.Meta[mcpServerStatusMetaKey] = status
		return &fallback
	}
	if server.Meta == nil {
		server.Meta = map[string]interface{}{}
	}
	server.Meta[mcpServerStatusMetaKey] = status
	return server
}

// resolvePriority validates the optional priority pointer and returns
// the effective value (defaulted when nil). Second return is false on
// out-of-range input.
func resolvePriority(p *int32) (int32, bool) {
	if p == nil {
		return defaultMCPServerPriority, true
	}
	if *p < mcpPriorityMin || *p > mcpPriorityMax {
		return 0, false
	}
	return *p, true
}

// createBulkMCPServerCR is the CR-backed write path for
// POST /api/v1/registry/upload/bulk. All-or-nothing: every successful
// Create is appended to `created`; on any subsequent failure we walk
// `created` in reverse and Delete each (best-effort — secondary errors
// are logged but not surfaced, since the caller already has a primary
// cause). No readiness polling — bulk could be 100+ entries and per-
// entry polling would block the request for minutes.
func (h *RegistryHandler) createBulkMCPServerCR(c *gin.Context, reqs []UploadRegistryEntryRequest, userID string) {
	ctx := c.Request.Context()
	created := make([]*mcpv1alpha1.MCPServer, 0, len(reqs))

	for i := range reqs {
		req := &reqs[i]
		priority, _ := resolvePriority(req.Priority) // already validated by caller

		cr := mcpServerRequestToCR(req, h.namespace, userID)
		if err := h.crClient.Create(ctx, cr); err != nil {
			h.rollbackBulkCreates(ctx, created)
			if apierrors.IsAlreadyExists(err) {
				c.JSON(http.StatusConflict, gin.H{
					"error": fmt.Sprintf("MCPServer %q already exists (index %d); bulk upload rolled back", req.ID, i),
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to create MCPServer %q (index %d): %v; bulk upload rolled back", req.ID, i, err),
			})
			return
		}
		created = append(created, cr)

		if err := h.setMCPServerPriorityWithRetry(ctx, cr, priority); err != nil {
			h.rollbackBulkCreates(ctx, created)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to set priority on MCPServer %q (index %d): %v; bulk upload rolled back", req.ID, i, err),
			})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": fmt.Sprintf("Successfully uploaded %d MCP servers", len(reqs)),
		"count":   len(reqs),
	})
}

// rollbackBulkCreates deletes each entry in `created` in reverse order.
// IsNotFound races are silent; other errors are logged but not returned
// so the caller's primary error stays the surfaced cause.
func (h *RegistryHandler) rollbackBulkCreates(ctx context.Context, created []*mcpv1alpha1.MCPServer) {
	for i := len(created) - 1; i >= 0; i-- {
		cr := created[i]
		if err := h.crClient.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
			log.Printf("bulk rollback: failed to delete MCPServer %q: %v", cr.Name, err)
		}
	}
}
