package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/mcp"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
	registryadmin "github.com/SUSE/suse-ai-up/pkg/services/registry/admin"
	registryloader "github.com/SUSE/suse-ai-up/pkg/services/registry/loader"
)

// compile-time check that DefaultRegistryManager satisfies the consolidated
// loader's Manager interface in pkg/services/registry/loader.
var _ registryloader.Manager = (*DefaultRegistryManager)(nil)

// ServerType represents the type of MCP server
type ServerType string

const (
	ServerTypeLocalStdio ServerType = "localstdio"
	ServerTypeRemoteHTTP ServerType = "remotehttp"
	ServerTypeGitHub     ServerType = "github"
)

type RegistryManagerInterface interface {
	UploadRegistryEntries(entries []*models.MCPServer) error
	LoadFromCustomSource(sourceURL string) error
	SearchServers(query string, filters map[string]interface{}) ([]*models.MCPServer, error)
	Clear() error
}

// MCPServerStore interface for MCP server storage operations
type MCPServerStore interface {
	CreateMCPServer(server *models.MCPServer) error
	GetMCPServer(id string) (*models.MCPServer, error)
	UpdateMCPServer(id string, updated *models.MCPServer) error
	DeleteMCPServer(id string) error
	ListMCPServers() []*models.MCPServer
}

// RegistryHandler handles MCP server registry operations
type RegistryHandler struct {
	Store            MCPServerStore
	RegistryManager  RegistryManagerInterface
	AdapterStore     clients.AdapterResourceStore
	ToolDiscovery    *mcp.MCPToolDiscoveryService
	UserGroupService *services.UserGroupService
	Config           *config.Config
	K8sClient        kubernetes.Interface
	AdminService     *registryadmin.Service
}

// NewRegistryHandler creates a new registry handler
func NewRegistryHandler(store MCPServerStore, registryManager RegistryManagerInterface, adapterStore clients.AdapterResourceStore, userGroupService *services.UserGroupService, cfg *config.Config, k8sClient kubernetes.Interface, adminService *registryadmin.Service) *RegistryHandler {
	return &RegistryHandler{
		Store:            store,
		RegistryManager:  registryManager,
		AdapterStore:     adapterStore,
		ToolDiscovery:    mcp.NewMCPToolDiscoveryService(),
		UserGroupService: userGroupService,
		Config:           cfg,
		K8sClient:        k8sClient,
		AdminService:     adminService,
	}
}

// DetectServerType determines the type of MCP server from registry metadata and package information
func DetectServerType(server *models.MCPServer) ServerType {
	if server.GitHubConfig != nil || (server.Meta != nil && server.Meta["source"] == "github") {
		return ServerTypeGitHub
	}

	if server.Meta != nil {
		if source, ok := server.Meta["source"].(string); ok {
			switch strings.ToLower(source) {
			case "localstdio", "stdio", "local":
				return ServerTypeLocalStdio
			case "remote", "remotehttp", "http":
				return ServerTypeRemoteHTTP
			}
		}
	}

	if len(server.Packages) > 0 {
		transport := server.Packages[0].Transport.Type
		switch strings.ToLower(transport) {
		case "stdio":
			return ServerTypeLocalStdio
		case "http", "sse", "websocket":
			return ServerTypeRemoteHTTP
		}
	}

	if server.URL != "" {
		return ServerTypeRemoteHTTP
	}

	return ServerTypeLocalStdio
}

// GetMCPServer handles GET /registry/{id}
// @Summary Get an MCP server by ID
// @Description Retrieve a specific MCP server configuration
// @Tags registry
// @Produce json
// @Param id path string true "MCP Server ID"
// @Success 200 {object} models.MCPServer
// @Failure 404 {string} string "Not Found"
// @Router /api/v1/registry/{id} [get]
func (h *RegistryHandler) GetMCPServer(c *gin.Context) {
	id := c.Param("id")
	server, err := h.Store.GetMCPServer(id)
	if err != nil {
		log.Printf("MCP server not found: %s", id)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, server)
}

// UpdateMCPServer handles PUT /registry/{id}
// @Summary Update an MCP server
// @Description Update an existing MCP server configuration or validation status
// @Tags registry
// @Accept json
// @Produce json
// @Param id path string true "MCP Server ID"
// @Param server body models.MCPServer true "Updated MCP server data"
// @Success 200 {object} models.MCPServer
// @Failure 400 {string} string "Bad Request"
// @Failure 404 {string} string "Not Found"
// @Router /api/v1/registry/{id} [put]
func (h *RegistryHandler) UpdateMCPServer(c *gin.Context) {
	id := c.Param("id")
	var updated models.MCPServer
	if err := c.ShouldBindJSON(&updated); err != nil {
		log.Printf("Error decoding MCP server update: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.Store.UpdateMCPServer(id, &updated); err != nil {
		log.Printf("Error updating MCP server: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Updated MCP server: %s", id)
	c.JSON(http.StatusOK, updated)
}

// DeleteMCPServer handles DELETE /registry/{id}
// @Summary Delete an MCP server
// @Description Remove an MCP server entry
// @Tags registry
// @Param id path string true "MCP Server ID"
// @Success 204 "No Content"
// @Failure 404 {string} string "Not Found"
// @Router /api/v1/registry/{id} [delete]
func (h *RegistryHandler) DeleteMCPServer(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.DeleteMCPServer(id); err != nil {
		log.Printf("Error deleting MCP server: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Deleted MCP server: %s", id)
	c.Status(http.StatusNoContent)
}

// ListMCPServersFiltered lists servers with permission-based filtering
func (h *RegistryHandler) ListMCPServersFiltered(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	allServers := h.Store.ListMCPServers()

	canSeeAll := false
	if h.UserGroupService != nil {
		if canManage, err := h.UserGroupService.CanManageGroups(r.Context(), userID); err == nil && canManage {
			canSeeAll = true
		}
	}

	if canSeeAll {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(allServers)
		return
	}

	var filteredServers []*models.MCPServer
	for _, server := range allServers {
		if canAccess, _ := h.UserGroupService.CanAccessServer(r.Context(), userID, server.ID); canAccess {
			filteredServers = append(filteredServers, server)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredServers)
}

// BrowseRegistry handles GET /registry/browse
// @Summary Browse registry servers with search and filters
// @Description Search and filter MCP servers from local YAML configuration
// @Tags registry
// @Produce json
// @Param q query string false "Search query"
// @Param transport query string false "Filter by transport type (stdio, sse, websocket)"
// @Param registryType query string false "Filter by registry type (oci, npm)"
// @Param validationStatus query string false "Filter by validation status"
// @Param source query string false "Filter by source (yaml)"
// @Success 200 {array} models.MCPServer
// @Router /api/v1/registry/browse [get]
func (h *RegistryHandler) BrowseRegistry(c *gin.Context) {
	query := c.Query("q")
	transport := c.Query("transport")
	registryType := c.Query("registryType")
	validationStatus := c.Query("validationStatus")
	source := c.Query("source")

	log.Printf("BrowseRegistry called with query=%s, transport=%s, registryType=%s, validationStatus=%s, source=%s",
		query, transport, registryType, validationStatus, source)

	allServers := h.Store.ListMCPServers()
	log.Printf("Found %d servers in registry", len(allServers))

	var filteredServers []*models.MCPServer

	for _, server := range allServers {
		if query != "" {
			if !strings.Contains(strings.ToLower(server.Name), strings.ToLower(query)) &&
				!strings.Contains(strings.ToLower(server.Description), strings.ToLower(query)) {
				continue
			}
		}

		if transport != "" {
			hasTransport := false
			for _, pkg := range server.Packages {
				if pkg.Transport.Type == transport {
					hasTransport = true
					break
				}
			}
			if !hasTransport {
				continue
			}
		}

		if registryType != "" {
			hasRegistryType := false
			for _, pkg := range server.Packages {
				if pkg.RegistryType == registryType {
					hasRegistryType = true
					break
				}
			}
			if !hasRegistryType {
				continue
			}
		}

		if validationStatus != "" && server.ValidationStatus != validationStatus {
			continue
		}

		if source != "" {
			if server.Meta == nil || server.Meta["registry_source"] != source {
				continue
			}
		}

		filteredServers = append(filteredServers, server)
	}

	log.Printf("Filtered to %d servers", len(filteredServers))
	c.JSON(http.StatusOK, filteredServers)
}
