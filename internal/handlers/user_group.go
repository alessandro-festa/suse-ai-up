package handlers

import (
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SUSE/suse-ai-up/pkg/services"
)

// UserGroupHandler handles user and group management requests.
//
// crClient + namespace are the P2.4f write-through wiring. When both are
// set, Create/Update/Delete for User and Group write CRs through the
// controller-runtime client (so UserReconciler / GroupReconciler own the
// projection back into the auth store). When unset, the handler falls
// back to userGroupService for backwards compatibility.
type UserGroupHandler struct {
	userGroupService *services.UserGroupService
	crClient         client.Client
	namespace        string
}

// NewUserGroupHandler creates a new user/group handler. Use WithCRClient
// to enable CR-backed write-through (P2.4f).
func NewUserGroupHandler(userGroupService *services.UserGroupService) *UserGroupHandler {
	return &UserGroupHandler{
		userGroupService: userGroupService,
	}
}

// WithCRClient enables CR-backed write-through. When set, write handlers
// project requests onto User / Group CRs and poll Status.Conditions[Ready]
// before responding. Returns the handler for chaining.
func (h *UserGroupHandler) WithCRClient(c client.Client, namespace string) *UserGroupHandler {
	h.crClient = c
	h.namespace = namespace
	return h
}

// HandleUsers handles both listing and creating users
func (h *UserGroupHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListUsers(w, r)
	case http.MethodPost:
		h.CreateUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleGroups handles both listing and creating groups
func (h *UserGroupHandler) HandleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListGroups(w, r)
	case http.MethodPost:
		h.CreateGroup(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
