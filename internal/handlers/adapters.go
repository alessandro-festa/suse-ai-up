package handlers

import (
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
	adaptersvc "github.com/SUSE/suse-ai-up/pkg/services/adapters"
	authsvc "github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// AdapterHandler handles adapter management requests.
//
// crClient + namespace are the P2.4d write-through wiring. When both are
// set, CreateAdapter/UpdateAdapter/DeleteAdapter write Adapter CRs through
// the controller-runtime client (so AdapterReconciler owns the resulting
// Deployment+Service). When unset, the handler falls back to adapterService
// for backwards compatibility with non-operator callers (registry service,
// tests).
type AdapterHandler struct {
	adapterService     *adaptersvc.AdapterService
	userGroupService   *services.UserGroupService
	crClient           client.Client
	namespace          string
	assignmentRegistry authsvc.AssignmentRegistry
}

// NewAdapterHandler creates a new adapter handler. Use WithCRClient to
// enable CR-backed write-through (P2.4d).
func NewAdapterHandler(adapterService *adaptersvc.AdapterService, userGroupService *services.UserGroupService) *AdapterHandler {
	return &AdapterHandler{
		adapterService:   adapterService,
		userGroupService: userGroupService,
	}
}

// WithCRClient enables CR-backed write-through. When set, write handlers
// project requests onto Adapter CRs and poll Status.Conditions[Ready]
// before responding. Returns the handler for chaining.
func (h *AdapterHandler) WithCRClient(c client.Client, namespace string) *AdapterHandler {
	h.crClient = c
	h.namespace = namespace
	return h
}

// WithAssignmentRegistry enables RouteAssignment ACL enforcement on the
// MCP hot path. When set, HandleMCPProtocol computes the effective ACL
// set (explicit Adapter.Spec.RouteAssignmentRefs ∪ server-scoped
// assignments matching Spec.MCPServerRef) and rejects requests whose
// authenticated subject doesn't satisfy any assignment at the required
// permission level. When unset, the hot path is unconditionally
// allow-all (legacy stub behavior). Returns the handler for chaining.
func (h *AdapterHandler) WithAssignmentRegistry(r authsvc.AssignmentRegistry) *AdapterHandler {
	h.assignmentRegistry = r
	return h
}

// CreateAdapterRequest represents a request to create an adapter
type CreateAdapterRequest struct {
	MCPServerID          string                    `json:"mcpServerId"`
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	EnvironmentVariables map[string]string         `json:"environmentVariables"`
	Authentication       *models.AdapterAuthConfig `json:"authentication"`
	DeploymentMethod     string                    `json:"deploymentMethod,omitempty"`
}

// CreateAdapterResponse represents the response for adapter creation
type CreateAdapterResponse struct {
	ID              string                   `json:"id"`
	MCPServerID     string                   `json:"mcpServerId"`
	MCPClientConfig map[string]interface{}   `json:"mcpClientConfig"`
	Capabilities    *models.MCPFunctionality `json:"capabilities"`
	Status          string                   `json:"status"`
	CreatedAt       time.Time                `json:"createdAt"`
}

// ListAdapterResponse represents an adapter in the list response
type ListAdapterResponse struct {
	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Description     string                   `json:"description,omitempty"`
	URL             string                   `json:"url"`
	MCPClientConfig map[string]interface{}   `json:"mcpClientConfig"`
	Capabilities    *models.MCPFunctionality `json:"capabilities,omitempty"`
	Status          string                   `json:"status"`
	CreatedAt       time.Time                `json:"createdAt"`
	LastUpdatedAt   time.Time                `json:"lastUpdatedAt"`
	CreatedBy       string                   `json:"createdBy"`
	ConnectionType  models.ConnectionType    `json:"connectionType"`
}

// HandleAdapters handles both listing and creating adapters
// @Summary List adapters
// @Description List all adapters for the current user
// @Tags adapters
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Success 200 {array} models.AdapterResource "List of adapters"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters [get]
func (h *AdapterHandler) HandleAdapters(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListAdapters(w, r)
	case http.MethodPost:
		h.CreateAdapter(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
