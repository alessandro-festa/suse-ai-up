package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/plugins"
	"github.com/gin-gonic/gin"
)

// CR write-path pacing for the Plugin CR write-through (P2.4e). The
// poll target is PluginConditionRegistered which the reconciler flips
// True on its first reconcile (independent of the health probe), so 5s
// is more than enough in the happy case. On timeout the response
// carries status="provisioning" so the UI can poll GET.
const (
	pluginPollInterval = 250 * time.Millisecond
	pluginPollTimeout  = 5 * time.Second
)

// PluginHandler handles plugin service registration and management.
//
// crClient + namespace are the P2.4e write-through wiring. When both are
// set, RegisterService / UnregisterService write Plugin CRs through the
// controller-runtime client (so PluginReconciler reflects them into
// ServiceManager and `kubectl get plugins` sees every UI-registered
// plugin). When unset, the handler falls back to ServiceManager directly
// for backwards compatibility.
type PluginHandler struct {
	serviceManager *plugins.ServiceManager
	crClient       client.Client
	namespace      string
}

// NewPluginHandler creates a new plugin handler. Use WithCRClient to
// enable CR-backed write-through (P2.4e).
func NewPluginHandler(serviceManager *plugins.ServiceManager) *PluginHandler {
	return &PluginHandler{
		serviceManager: serviceManager,
	}
}

// WithCRClient enables CR-backed write-through. When set, Register and
// Unregister project requests onto Plugin CRs and poll
// Status.Conditions[Registered] before responding. Returns the handler
// for chaining.
func (h *PluginHandler) WithCRClient(c client.Client, namespace string) *PluginHandler {
	h.crClient = c
	h.namespace = namespace
	return h
}

// RegisterServiceRequest represents a service registration request
type RegisterServiceRequest struct {
	ServiceID    string                      `json:"service_id" binding:"required"`
	ServiceType  string                      `json:"service_type" binding:"required"`
	ServiceURL   string                      `json:"service_url" binding:"required"`
	Version      string                      `json:"version"`
	Capabilities []plugins.ServiceCapability `json:"capabilities"`
}

// RegisterServiceResponse represents a service registration response.
//
// Status is a P2.4e additive field: "registered" once the reconciler
// flips PluginConditionRegistered=True; "provisioning" if the response
// returns before that (UI should poll GET to observe the eventual
// state). The legacy non-CR path always sets "registered".
type RegisterServiceResponse struct {
	Message   string `json:"message"`
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
}

// RegisterService handles POST /api/v1/plugins/register
// @Summary Register a plugin service
// @Description Register a new plugin service with the proxy
// @Tags plugins
// @Accept json
// @Produce json
// @Param request body RegisterServiceRequest true "Service registration request"
// @Success 201 {object} RegisterServiceResponse
// @Failure 400 {object} PluginErrorResponse
// @Failure 409 {object} PluginErrorResponse
// @Failure 500 {object} PluginErrorResponse
// @Router /api/v1/plugins/register [post]
func (h *PluginHandler) RegisterService(c *gin.Context) {
	var req RegisterServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Plugin registration: Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, PluginErrorResponse{Error: "Invalid request body", Details: err.Error()})
		return
	}

	log.Printf("Plugin registration: Registering service %s of type %s at %s",
		req.ServiceID, req.ServiceType, req.ServiceURL)

	if h.crClient != nil {
		h.registerPluginCR(c, &req)
		return
	}

	// Legacy path: in-memory ServiceManager only.
	serviceType := plugins.ServiceType(req.ServiceType)
	registration := &plugins.ServiceRegistration{
		ServiceID:    req.ServiceID,
		ServiceType:  serviceType,
		ServiceURL:   req.ServiceURL,
		Capabilities: req.Capabilities,
		Version:      req.Version,
	}

	if err := h.serviceManager.RegisterService(registration); err != nil {
		log.Printf("Plugin registration: Failed to register service %s: %v", req.ServiceID, err)
		c.JSON(http.StatusConflict, PluginErrorResponse{Error: "Failed to register service", Details: err.Error()})
		return
	}

	log.Printf("Plugin registration: Successfully registered service %s", req.ServiceID)

	c.JSON(http.StatusCreated, RegisterServiceResponse{
		Message:   "Service registered successfully",
		ServiceID: req.ServiceID,
		Status:    "registered",
	})
}

// UnregisterService handles DELETE /api/v1/plugins/register/{serviceId}
// @Summary Unregister a plugin service
// @Description Remove a plugin service registration
// @Tags plugins
// @Param serviceId path string true "Service ID"
// @Success 204 "No Content"
// @Failure 404 {object} PluginErrorResponse
// @Failure 500 {object} PluginErrorResponse
// @Router /api/v1/plugins/register/{serviceId} [delete]
func (h *PluginHandler) UnregisterService(c *gin.Context) {
	serviceID := c.Param("serviceId")

	log.Printf("Plugin registration: Unregistering service %s", serviceID)

	if h.crClient != nil {
		h.unregisterPluginCR(c, serviceID)
		return
	}

	if err := h.serviceManager.UnregisterService(serviceID); err != nil {
		log.Printf("Plugin registration: Failed to unregister service %s: %v", serviceID, err)
		c.JSON(http.StatusNotFound, PluginErrorResponse{Error: "Service not found", Details: err.Error()})
		return
	}

	log.Printf("Plugin registration: Successfully unregistered service %s", serviceID)
	c.Status(http.StatusNoContent)
}

// ListServices handles GET /api/v1/plugins/services
// @Summary List all registered plugin services
// @Description Get a list of all registered plugin services
// @Tags plugins
// @Produce json
// @Success 200 {array} plugins.ServiceRegistration
// @Router /api/v1/plugins/services [get]
func (h *PluginHandler) ListServices(c *gin.Context) {
	services := h.serviceManager.GetAllServices()
	c.JSON(http.StatusOK, services)
}

// GetService handles GET /api/v1/plugins/services/{serviceId}
// @Summary Get service details
// @Description Get details of a specific plugin service
// @Tags plugins
// @Produce json
// @Param serviceId path string true "Service ID"
// @Success 200 {object} plugins.ServiceRegistration
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/plugins/services/{serviceId} [get]
func (h *PluginHandler) GetService(c *gin.Context) {
	serviceID := c.Param("serviceId")

	service, exists := h.serviceManager.GetService(serviceID)
	if !exists {
		c.JSON(http.StatusNotFound, PluginErrorResponse{Error: "Service not found", Details: fmt.Sprintf("Service '%s' not found", serviceID)})
		return
	}

	c.JSON(http.StatusOK, service)
}

// ListServicesByType handles GET /api/v1/plugins/services/type/{serviceType}
// @Summary List services by type
// @Description Get all services of a specific type
// @Tags plugins
// @Produce json
// @Param serviceType path string true "Service type (smartagents or registry)"
// @Success 200 {array} plugins.ServiceRegistration
// @Failure 400 {object} PluginErrorResponse
// @Router /api/v1/plugins/services/type/{serviceType} [get]
func (h *PluginHandler) ListServicesByType(c *gin.Context) {
	serviceTypeStr := c.Param("serviceType")

	var serviceType plugins.ServiceType
	// Allow any service type
	serviceType = plugins.ServiceType(serviceTypeStr)

	services := h.serviceManager.GetServicesByType(serviceType)
	c.JSON(http.StatusOK, services)
}

// GetServiceHealth handles GET /api/v1/plugins/services/{serviceId}/health
// @Summary Get service health
// @Description Get the health status of a specific plugin service
// @Tags plugins
// @Produce json
// @Param serviceId path string true "Service ID"
// @Success 200 {object} plugins.ServiceHealth
// @Failure 404 {object} PluginErrorResponse
// @Router /api/v1/plugins/services/{serviceId}/health [get]
func (h *PluginHandler) GetServiceHealth(c *gin.Context) {
	serviceID := c.Param("serviceId")

	health, exists := h.serviceManager.GetServiceHealth(serviceID)
	if !exists {
		c.JSON(http.StatusNotFound, PluginErrorResponse{Error: "Service not found", Details: fmt.Sprintf("Service '%s' not found", serviceID)})
		return
	}

	c.JSON(http.StatusOK, health)
}

// PluginErrorResponse represents a plugin error response
type PluginErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// registerPluginCR is the CR-backed write path. It projects req into a
// Plugin CR, creates it, polls Status.Conditions[Registered], and
// returns the same RegisterServiceResponse shape the legacy path
// produces (with the additive Status field set per outcome).
func (h *PluginHandler) registerPluginCR(c *gin.Context, req *RegisterServiceRequest) {
	cr := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.ServiceID,
			Namespace: h.namespace,
		},
		Spec: mcpv1alpha1.PluginSpec{
			ServiceType:  mcpv1alpha1.PluginServiceType(req.ServiceType),
			ServiceURL:   req.ServiceURL,
			Version:      req.Version,
			Capabilities: translatePluginCapabilities(req.Capabilities),
		},
	}

	if err := h.crClient.Create(c.Request.Context(), cr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			c.JSON(http.StatusConflict, PluginErrorResponse{Error: "Failed to register service", Details: fmt.Sprintf("plugin %q already exists", req.ServiceID)})
			return
		}
		log.Printf("Plugin registration: Failed to create Plugin CR %s: %v", req.ServiceID, err)
		c.JSON(http.StatusInternalServerError, PluginErrorResponse{Error: "Failed to create Plugin CR", Details: err.Error()})
		return
	}

	status := h.pollPluginRegistered(c.Request.Context(), cr.Name)
	log.Printf("Plugin registration: Successfully created Plugin CR %s (status=%s)", req.ServiceID, status)

	c.JSON(http.StatusCreated, RegisterServiceResponse{
		Message:   "Service registered successfully",
		ServiceID: req.ServiceID,
		Status:    status,
	})
}

// unregisterPluginCR removes the Plugin CR. PluginReconciler's tombstone
// path (plugin_controller.go:84) cleans the ServiceManager entry via
// removeFromStore; no polling needed.
func (h *PluginHandler) unregisterPluginCR(c *gin.Context, serviceID string) {
	cr := &mcpv1alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceID,
			Namespace: h.namespace,
		},
	}
	if err := h.crClient.Delete(c.Request.Context(), cr); err != nil {
		if apierrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, PluginErrorResponse{Error: "Service not found", Details: fmt.Sprintf("plugin %q not found", serviceID)})
			return
		}
		log.Printf("Plugin registration: Failed to delete Plugin CR %s: %v", serviceID, err)
		c.JSON(http.StatusInternalServerError, PluginErrorResponse{Error: "Failed to delete Plugin CR", Details: err.Error()})
		return
	}
	log.Printf("Plugin registration: Successfully deleted Plugin CR %s", serviceID)
	c.Status(http.StatusNoContent)
}

// pollPluginRegistered waits up to pluginPollTimeout for the reconciler
// to flip PluginConditionRegistered=True. Returns "registered" on
// success or "provisioning" on timeout / ctx-done; the caller renders
// either into the response Status field.
func (h *PluginHandler) pollPluginRegistered(ctx context.Context, name string) string {
	deadline := time.Now().Add(pluginPollTimeout)
	var latest mcpv1alpha1.Plugin
	for {
		if err := h.crClient.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: name}, &latest); err == nil {
			for _, cond := range latest.Status.Conditions {
				if cond.Type == mcpv1alpha1.PluginConditionRegistered && cond.Status == metav1.ConditionTrue {
					return "registered"
				}
			}
		}
		if time.Now().After(deadline) {
			return "provisioning"
		}
		select {
		case <-ctx.Done():
			return "provisioning"
		case <-time.After(pluginPollInterval):
		}
	}
}

// translatePluginCapabilities maps the HTTP capability DTO onto the
// CR-shaped PluginCapability list. The two shapes are byte-identical
// today; the helper keeps the translation explicit so any future
// divergence has one place to update.
func translatePluginCapabilities(in []plugins.ServiceCapability) []mcpv1alpha1.PluginCapability {
	if len(in) == 0 {
		return nil
	}
	out := make([]mcpv1alpha1.PluginCapability, 0, len(in))
	for _, cap := range in {
		out = append(out, mcpv1alpha1.PluginCapability{
			Path:        cap.Path,
			Methods:     append([]string(nil), cap.Methods...),
			Description: cap.Description,
		})
	}
	return out
}
