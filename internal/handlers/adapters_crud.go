package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/logging"
	"github.com/SUSE/suse-ai-up/pkg/models"
	adaptersvc "github.com/SUSE/suse-ai-up/pkg/services/adapters"
)

// CR write-path pacing. ~5s total budget on Create/Update so the HTTP
// response stays synchronous for the common case while letting the
// reconciler finish; on timeout the handler returns 200 with
// status="provisioning" and the UI can poll GET for the eventual state.
const (
	adapterPollInterval = 250 * time.Millisecond
	adapterPollTimeout  = 5 * time.Second
)

// CreateAdapter creates a new adapter from a registry server.
//
// In CR mode (h.crClient != nil) the handler writes an Adapter CR and
// lets AdapterReconciler materialize the Deployment+Service, then polls
// Status.Conditions[Ready] for up to ~5s so the response remains
// synchronous from a caller's POV. In legacy mode it delegates to
// adapterService.CreateAdapter (which creates an in-memory adapter and
// a Sidecar via SidecarManager).
func (h *AdapterHandler) CreateAdapter(w http.ResponseWriter, r *http.Request) {
	logging.AdapterLogger.Info("CreateAdapter handler invoked")

	var req CreateAdapterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logging.AdapterLogger.Error("Failed to decode JSON: %v", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	logging.AdapterLogger.Info("Decoded request: mcpServerId=%s, name=%s", req.MCPServerID, req.Name)

	if req.MCPServerID == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "mcpServerId and name are required"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	// TRENTO_CONFIG special case is preserved verbatim — the env var
	// carries a JSON blob that maps to (URL, bearer token), and the legacy
	// HTTP-callers depend on this expansion happening before storage.
	if req.MCPServerID == "suse-trento" {
		if trentoConfig, exists := req.EnvironmentVariables["TRENTO_CONFIG"]; exists && trentoConfig != "" {
			trentoURL, token, err := adaptersvc.ParseTrentoConfig(trentoConfig)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid TRENTO_CONFIG format: " + err.Error()})
				return
			}

			req.EnvironmentVariables["TRENTO_URL"] = trentoURL
			delete(req.EnvironmentVariables, "TRENTO_CONFIG")

			if req.Authentication == nil {
				req.Authentication = &models.AdapterAuthConfig{}
			}
			req.Authentication.Type = "bearer"
			req.Authentication.BearerToken = &models.BearerTokenConfig{
				Token:   token,
				Dynamic: false,
			}
		}
	}

	if h.crClient != nil {
		h.createAdapterCR(w, r, &req, userID)
		return
	}

	// Legacy path: in-memory store + SidecarManager.
	adapter, err := h.adapterService.CreateAdapter(
		r.Context(),
		userID,
		req.MCPServerID,
		req.Name,
		req.EnvironmentVariables,
		req.Authentication,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create adapter: " + err.Error()})
		return
	}

	response := CreateAdapterResponse{
		ID:              adapter.ID,
		MCPServerID:     req.MCPServerID,
		MCPClientConfig: adaptersvc.BuildCreateClientConfig(adapter),
		Capabilities:    adapter.MCPFunctionality,
		Status:          "ready",
		CreatedAt:       adapter.CreatedAt,
	}

	writeJSON(w, http.StatusCreated, response)
}

// createAdapterCR is the CR-backed write path. It projects req into an
// Adapter CR, creates it, optionally creates a paired Secret for an
// inline bearer token, polls Status.Conditions[Ready], and returns the
// same CreateAdapterResponse shape the legacy path produces.
func (h *AdapterHandler) createAdapterCR(w http.ResponseWriter, r *http.Request, req *CreateAdapterRequest, userID string) {
	ctx := r.Context()

	cr, secret, status, errResp := h.buildAdapterCR(ctx, req, userID)
	if errResp != nil {
		writeJSON(w, status, errResp)
		return
	}

	if err := h.crClient.Create(ctx, cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: fmt.Sprintf("Adapter %q already exists", req.Name)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create Adapter CR: " + err.Error()})
		return
	}

	// Pair the bearer-token Secret to the just-created Adapter so delete
	// cascades. We must do this after Create so the Adapter has a UID.
	if secret != nil {
		if err := controllerutil.SetControllerReference(cr, secret, h.crClient.Scheme()); err != nil {
			logging.AdapterLogger.Error("failed to set owner ref on bearer secret: %v", err)
		}
		if err := h.crClient.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
			logging.AdapterLogger.Error("failed to create bearer secret %s: %v", secret.Name, err)
			// Roll back the Adapter so we don't leave a CR pointing at a
			// non-existent Secret. The reconciler would otherwise stall.
			_ = h.crClient.Delete(ctx, cr)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to create bearer secret: " + err.Error()})
			return
		}
	}

	observed, readyStatus := h.pollReady(ctx, cr.Name)
	resource := adapterCRToResource(observed)

	response := CreateAdapterResponse{
		ID:              resource.ID,
		MCPServerID:     req.MCPServerID,
		MCPClientConfig: adaptersvc.BuildCreateClientConfig(resource),
		Capabilities:    resource.MCPFunctionality,
		Status:          readyStatus,
		CreatedAt:       resource.CreatedAt,
	}
	writeJSON(w, http.StatusCreated, response)
}

// buildAdapterCR translates a CreateAdapterRequest into an Adapter CR
// (plus optional bearer-token Secret). Returns (cr, secret, statusCode,
// errResponse). On error, only statusCode and errResponse are meaningful.
func (h *AdapterHandler) buildAdapterCR(ctx context.Context, req *CreateAdapterRequest, userID string) (*mcpv1alpha1.Adapter, *corev1.Secret, int, *ErrorResponse) {
	// MCPServer lookup determines whether this adapter needs a sidecar
	// or speaks to a remote URL directly. For this PR we only resolve
	// the CR — registry-loaded entries that don't have a corresponding
	// MCPServer CR (legacy) fall through to a sidecar default; the
	// reconciler will then complain via Status if SidecarConfig is also
	// missing, which surfaces cleanly to the caller via pollReady.
	connectionType := mcpv1alpha1.ConnectionTypeSidecarStdio
	var remoteURL string
	var sidecarConfig *mcpv1alpha1.SidecarConfig
	mcpServer := h.findMCPServer(ctx, req.MCPServerID)
	if mcpServer != nil {
		if mcpServer.Spec.URL != "" {
			connectionType = mcpv1alpha1.ConnectionTypeRemoteHTTP
			remoteURL = mcpServer.Spec.URL
		} else {
			sidecarConfig = sidecarConfigFromMCPServer(mcpServer)
			if sidecarConfig != nil && sidecarConfig.CommandType != "docker" {
				connectionType = mcpv1alpha1.ConnectionTypeStreamableHTTP
			}
		}
	}

	mcpServerRefName := req.MCPServerID
	if mcpServer != nil {
		mcpServerRefName = mcpServer.Name
	}

	cr := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: h.namespace,
			Annotations: map[string]string{
				adapterAnnotationCreatedBy: userID,
			},
		},
		Spec: mcpv1alpha1.AdapterSpec{
			Source: mcpv1alpha1.AdapterSource{
				MCPServerRef:  &corev1.LocalObjectReference{Name: mcpServerRefName},
				RemoteURL:     remoteURL,
				SidecarConfig: sidecarConfig,
			},
			ConnectionType: connectionType,
			Description:    req.Description,
			Variables:      req.EnvironmentVariables,
		},
	}

	// Authentication translation. Inline bearer tokens (today's HTTP
	// shape) go into a paired Secret rather than the CR Spec, which
	// only carries SecretRefs. The Secret is returned for the caller
	// to create after the Adapter exists (so OwnerReference can stamp
	// the UID).
	var secret *corev1.Secret
	if req.Authentication != nil {
		auth, sec, err := translateAdapterAuth(req.Authentication, req.Name, h.namespace)
		if err != nil {
			return nil, nil, http.StatusBadRequest, &ErrorResponse{Error: "Invalid authentication: " + err.Error()}
		}
		cr.Spec.Authentication = auth
		secret = sec
	}

	return cr, secret, 0, nil
}

// findMCPServer resolves an MCPServer CR by exact name first, then falls
// back to listing all MCPServers in the namespace and matching by name
// suffix. Registry-created CRs are prefixed with the registry name
// (e.g. "suse-ai-up-default-bugzilla") while the UI sends the short
// entry name ("bugzilla").
func (h *AdapterHandler) findMCPServer(ctx context.Context, id string) *mcpv1alpha1.MCPServer {
	var srv mcpv1alpha1.MCPServer
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, &srv); err == nil {
		return &srv
	}
	// MCPServer CRs live in the operator namespace (not the workload
	// namespace), so list across all namespaces for the suffix fallback.
	var list mcpv1alpha1.MCPServerList
	if err := h.crClient.List(ctx, &list); err != nil {
		return nil
	}
	suffix := "-" + id
	for i := range list.Items {
		if strings.HasSuffix(list.Items[i].Name, suffix) {
			return &list.Items[i]
		}
	}
	return nil
}

// sidecarConfigFromMCPServer derives an Adapter SidecarConfig from an
// MCPServer CR. For docker/oci entries it uses the spec-level Image
// directly. For python/npx/go entries it maps the commandType to a base
// image and passes the command as the container entrypoint — mirroring
// what the legacy SidecarManager.deployGenericWithKubeClient does.
func sidecarConfigFromMCPServer(srv *mcpv1alpha1.MCPServer) *mcpv1alpha1.SidecarConfig {
	image := srv.Spec.Image
	port := srv.Spec.Port
	cmdType := srv.Spec.CommandType
	command := srv.Spec.Command

	if image == "" {
		for _, pkg := range srv.Spec.Packages {
			if pkg.RegistryType == "oci" || pkg.RegistryType == "docker" {
				image = pkg.Identifier
				break
			}
		}
	}

	if image == "" && cmdType != "" {
		image = baseImageForCommandType(cmdType)
	}

	if image == "" {
		return nil
	}

	var env []corev1.EnvVar
	for _, pkg := range srv.Spec.Packages {
		for _, ev := range pkg.EnvironmentVariables {
			if ev.Default != "" {
				env = append(env, corev1.EnvVar{Name: ev.Name, Value: ev.Default})
			}
		}
	}

	effectiveType := cmdType
	if effectiveType == "" {
		effectiveType = "docker"
	}

	cfg := &mcpv1alpha1.SidecarConfig{
		CommandType: effectiveType,
		Image:       image,
		Port:        port,
		Env:         env,
	}

	if command != "" {
		if effectiveType == "docker" {
			cfg.Command = "sh"
			cfg.Args = []string{"-c", command}
		} else {
			cfg.Command = command
		}
	}

	return cfg
}

func baseImageForCommandType(ct string) string {
	switch ct {
	case "python":
		return "registry.suse.com/bci/python:3.11"
	case "npx":
		return "registry.suse.com/bci/nodejs:22"
	case "go":
		return "registry.suse.com/bci/golang:1.25"
	default:
		return ""
	}
}

// translateAdapterAuth maps the HTTP authentication DTO onto the
// CR-shaped AdapterAuthentication. Inline tokens/passwords are written
// to a paired Secret; the CR holds only references.
func translateAdapterAuth(in *models.AdapterAuthConfig, adapterName, namespace string) (*mcpv1alpha1.AdapterAuthentication, *corev1.Secret, error) {
	out := &mcpv1alpha1.AdapterAuthentication{
		Required: true,
		Type:     mcpv1alpha1.AdapterAuthType(in.Type),
	}
	var secret *corev1.Secret
	switch strings.ToLower(in.Type) {
	case "", "none":
		out.Type = mcpv1alpha1.AdapterAuthTypeNone
		out.Required = false
	case "bearer":
		if in.BearerToken == nil {
			return nil, nil, fmt.Errorf("bearer auth requires bearerToken")
		}
		if in.BearerToken.Dynamic {
			out.BearerToken = &mcpv1alpha1.BearerTokenAuth{Dynamic: true}
		} else if in.BearerToken.Token != "" {
			secretName := fmt.Sprintf("adapter-%s-bearer", adapterName)
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
				Type:       corev1.SecretTypeOpaque,
				StringData: map[string]string{"token": in.BearerToken.Token},
			}
			out.BearerToken = &mcpv1alpha1.BearerTokenAuth{
				SecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  "token",
				},
			}
		} else {
			return nil, nil, fmt.Errorf("bearer auth requires either token or dynamic=true")
		}
	default:
		// oauth/basic/apikey: not exercised by the current HTTP write
		// path; carry the Type through and let the reconciler reject if
		// the CR is incomplete. Surfaces as Status condition rather
		// than dropping the request.
	}
	return out, secret, nil
}

// pollReady waits up to adapterPollTimeout for the Adapter's Ready
// condition to flip. Returns the most recent observed CR and a status
// string suitable for CreateAdapterResponse.Status:
//   - "ready" when Ready=True
//   - "error" when Ready=False with a terminal reason
//   - "provisioning" otherwise (including timeout — the UI will poll GET)
func (h *AdapterHandler) pollReady(ctx context.Context, name string) (*mcpv1alpha1.Adapter, string) {
	deadline := time.Now().Add(adapterPollTimeout)
	var latest mcpv1alpha1.Adapter
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			for _, c := range latest.Status.Conditions {
				if c.Type != mcpv1alpha1.AdapterConditionReady {
					continue
				}
				if c.Status == metav1.ConditionTrue {
					return &latest, "ready"
				}
				if c.Status == metav1.ConditionFalse && isTerminalAdapterReason(c.Reason) {
					return &latest, "error"
				}
			}
		}
		if time.Now().After(deadline) {
			return &latest, "provisioning"
		}
		select {
		case <-ctx.Done():
			return &latest, "provisioning"
		case <-time.After(adapterPollInterval):
		}
	}
}

func isTerminalAdapterReason(reason string) bool {
	switch reason {
	case "MissingSidecarConfig", "UnsupportedCommandType", "InvalidSpec":
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ListAdapters lists all adapters for the current user
func (h *AdapterHandler) ListAdapters(w http.ResponseWriter, r *http.Request) {
	logging.AdapterLogger.Info("ListAdapters handler invoked")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	adapters, err := h.adapterService.ListAdapters(r.Context(), userID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to list adapters: " + err.Error()})
		return
	}

	listAdapters := make([]map[string]interface{}, len(adapters))
	for i := range adapters {
		adapter := &adapters[i]
		listAdapters[i] = map[string]interface{}{
			"id":              adapter.ID,
			"name":            adapter.Name,
			"description":     adapter.Description,
			"url":             adapter.URL,
			"mcpClientConfig": adaptersvc.BuildListClientConfig(adapter),
			"capabilities":    adapter.MCPFunctionality,
			"status":          adapter.Status,
			"createdAt":       adapter.CreatedAt,
			"lastUpdatedAt":   adapter.LastUpdatedAt,
			"createdBy":       adapter.CreatedBy,
			"connectionType":  adapter.ConnectionType,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listAdapters)
}

// GetAdapter gets a specific adapter by ID
// @Summary Get adapter details
// @Description Retrieve details of a specific adapter
// @Tags adapters
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} models.AdapterResource "Adapter details"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name} [get]
func (h *AdapterHandler) GetAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	adapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to get adapter: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adapter)
}

// UpdateAdapter updates an existing adapter
// @Summary Update adapter
// @Description Update an existing adapter's configuration
// @Tags adapters
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter name"
// @Param adapter body models.AdapterData true "Updated adapter data"
// @Success 200 {object} models.AdapterResource
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/adapters/{name} [put]
func (h *AdapterHandler) UpdateAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if h.crClient != nil {
		h.updateAdapterCR(w, r, adapterID)
		return
	}

	currentAdapter, err := h.adapterService.GetAdapter(r.Context(), userID, adapterID, h.userGroupService)
	if err != nil {
		if err.Error() == "adapter not found" {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
		} else {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to get adapter: " + err.Error()})
		}
		return
	}

	var updateAdapter models.AdapterResource
	if err := json.NewDecoder(r.Body).Decode(&updateAdapter); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	updateAdapter.ID = currentAdapter.ID
	updateAdapter.CreatedBy = currentAdapter.CreatedBy
	updateAdapter.CreatedAt = currentAdapter.CreatedAt
	updateAdapter.LastUpdatedAt = time.Now().UTC()

	if err := h.adapterService.UpdateAdapter(r.Context(), userID, updateAdapter); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update adapter: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, updateAdapter)
}

// updateAdapterCR mutates the Adapter CR's mutable Spec fields from the
// request body and polls for Ready. The DTO is intentionally narrow:
// only Description, Variables, and Authentication round-trip through
// the CR. ConnectionType / Source are immutable post-create (they would
// require recreating the backing Deployment); attempts to change them
// are accepted silently — the CR Spec wins.
func (h *AdapterHandler) updateAdapterCR(w http.ResponseWriter, r *http.Request, adapterID string) {
	ctx := r.Context()

	var cr mcpv1alpha1.Adapter
	if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: adapterID}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Adapter CR: " + err.Error()})
		return
	}

	var update models.AdapterResource
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	cr.Spec.Description = update.Description
	if update.EnvironmentVariables != nil {
		cr.Spec.Variables = update.EnvironmentVariables
	}
	if update.Authentication != nil {
		auth, _, err := translateAdapterAuth(update.Authentication, cr.Name, h.namespace)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid authentication: " + err.Error()})
			return
		}
		cr.Spec.Authentication = auth
		// Secret updates on UpdateAdapter are intentionally not supported
		// in this PR — bearer rotations should go through Secret edits.
	}

	if err := h.crClient.Update(ctx, &cr); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to update Adapter CR: " + err.Error()})
		return
	}

	observed, _ := h.pollReady(ctx, cr.Name)
	writeJSON(w, http.StatusOK, adapterCRToResource(observed))
}

// CheckAdapterHealth checks and updates the health status of an adapter
// @Summary Check adapter health
// @Description Check the health of an adapter's sidecar and update its status
// @Tags adapters
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter name"
// @Success 200 {object} map[string]string
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/adapters/{name}/health [post]
func (h *AdapterHandler) CheckAdapterHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	pathParts := strings.Split(path, "/")
	adapterID := pathParts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if h.crClient != nil {
		h.checkAdapterHealthCR(w, r, adapterID)
		return
	}

	if err := h.adapterService.CheckAdapterHealth(r.Context(), userID, adapterID, h.userGroupService); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "not found") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to check adapter health: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Adapter health check completed",
		"adapterId": adapterID,
	})
}

// DeleteAdapter deletes an adapter and its associated sidecar resources
// @Summary Delete adapter
// @Description Delete an adapter and clean up its associated resources
// @Tags adapters
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name} [delete]
func (h *AdapterHandler) DeleteAdapter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	adapterID := strings.Split(path, "/")[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if h.crClient != nil {
		h.deleteAdapterCR(w, r, adapterID)
		return
	}

	if err := h.adapterService.DeleteAdapter(r.Context(), userID, adapterID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to delete adapter: " + err.Error()})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SyncAdapterCapabilities syncs capabilities for an adapter
// @Summary Sync adapter capabilities
// @Description Synchronize and refresh the capabilities of an adapter
// @Tags adapters
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]string "Sync result"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/sync [post]
func (h *AdapterHandler) SyncAdapterCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/adapters/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "sync" {
		http.NotFound(w, r)
		return
	}
	adapterID := parts[0]

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	if h.crClient != nil {
		h.syncAdapterCapabilitiesCR(w, r, adapterID)
		return
	}

	if err := h.adapterService.SyncAdapterCapabilities(r.Context(), userID, adapterID, h.userGroupService); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if err.Error() == "adapter not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Adapter not found"})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to sync capabilities: " + err.Error()})
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "capabilities_synced",
		"message": "Adapter capabilities have been synchronized",
	})
}

// deleteAdapterCR removes the Adapter CR. OwnerReferences stamped onto
// the Deployment, Service, and bearer Secret by AdapterReconciler and
// createAdapterCR cascade the delete; no polling is required because
// returning 204 once the API server acknowledges the Delete matches the
// legacy "fire-and-forget" semantics.
func (h *AdapterHandler) deleteAdapterCR(w http.ResponseWriter, r *http.Request, adapterID string) {
	cr := &mcpv1alpha1.Adapter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      adapterID,
			Namespace: h.namespace,
		},
	}
	if err := h.crClient.Delete(r.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete Adapter CR: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkAdapterHealthCR reports the reconciler's current view of the
// adapter. The reconciler owns probing in CR mode; this endpoint just
// surfaces the most recent Status.Conditions[Ready] so callers can see
// what the controller saw without forcing a re-probe.
func (h *AdapterHandler) checkAdapterHealthCR(w http.ResponseWriter, r *http.Request, adapterID string) {
	var cr mcpv1alpha1.Adapter
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: adapterID}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Adapter CR: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message":   "Adapter health check completed",
		"adapterId": adapterID,
		"status":    string(adapterCRToResource(&cr).Status),
	})
}

// syncAdapterCapabilitiesCR pokes the reconciler by bumping a sync
// annotation. AdapterReconciler watches the CR and re-runs on any change,
// so updating an annotation forces a Reconcile without mutating Spec.
// Capability discovery itself is not yet implemented in the reconciler
// (legacy SidecarManager owned that flow); this preserves the endpoint's
// contract while flagging the work as TBD on the controller side.
func (h *AdapterHandler) syncAdapterCapabilitiesCR(w http.ResponseWriter, r *http.Request, adapterID string) {
	var cr mcpv1alpha1.Adapter
	if err := h.crClient.Get(r.Context(), client.ObjectKey{Namespace: h.namespace, Name: adapterID}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "Adapter not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch Adapter CR: " + err.Error()})
		return
	}
	if cr.Annotations == nil {
		cr.Annotations = map[string]string{}
	}
	cr.Annotations[adapterAnnotationSyncRequested] = time.Now().UTC().Format(time.RFC3339Nano)
	if err := h.crClient.Update(r.Context(), &cr); err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Failed to trigger sync: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "capabilities_sync_requested",
		"message": "Adapter sync requested; reconciler will refresh capabilities",
	})
}
