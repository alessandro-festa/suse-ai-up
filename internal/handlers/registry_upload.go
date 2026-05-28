package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/SUSE/suse-ai-up/pkg/models"
	registryadmin "github.com/SUSE/suse-ai-up/pkg/services/registry/admin"
)

// UploadRegistryEntryRequest is the wire shape for POST/PUT
// /api/v1/registry/upload. It embeds models.MCPServer so existing
// clients sending the bare model continue to decode unchanged, and adds
// an optional Priority that — in CR mode — is patched onto
// MCPServer.Status.Priority post-Create. Values outside [0, 1000] are
// rejected with 400.
type UploadRegistryEntryRequest struct {
	models.MCPServer
	Priority *int32 `json:"priority,omitempty"`
}

// UploadRegistryEntry handles POST /registry/upload
// @Summary Upload a single registry entry
// @Description Upload a single MCP server registry entry
// @Tags registry
// @Accept json
// @Produce json
// @Param server body UploadRegistryEntryRequest true "MCP server data"
// @Success 201 {object} models.MCPServer
// @Failure 400 {string} string "Bad Request"
// @Router /api/v1/registry/upload [post]
func (h *RegistryHandler) UploadRegistryEntry(c *gin.Context) {
	var req UploadRegistryEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error decoding MCP server: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	if req.Name == "" {
		log.Printf("MCP server name is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "MCP server name is required"})
		return
	}

	if req.ID == "" {
		req.ID = generateID()
	}

	if h.crClient != nil {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			userID = "default-user"
		}
		h.createMCPServerCR(c, &req, userID)
		return
	}

	if err := h.RegistryManager.UploadRegistryEntries([]*models.MCPServer{&req.MCPServer}); err != nil {
		log.Printf("Error uploading MCP server: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Uploaded MCP server: %s", req.ID)
	c.JSON(http.StatusCreated, req.MCPServer)
}

// UploadBulkRegistryEntries handles POST /registry/upload/bulk
// @Summary Upload multiple registry entries
// @Description Upload multiple MCP server registry entries in bulk
// @Tags registry
// @Accept json
// @Produce json
// @Param servers body []UploadRegistryEntryRequest true "Array of MCP server data"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {string} string "Bad Request"
// @Router /api/v1/registry/upload/bulk [post]
func (h *RegistryHandler) UploadBulkRegistryEntries(c *gin.Context) {
	var reqs []UploadRegistryEntryRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		log.Printf("Error decoding MCP servers: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// Validation-first: every entry must pass before we touch any store
	// or create any CR. Failures return 400 with the offending index so
	// the caller can localize the bad row in a large payload.
	seen := make(map[string]int, len(reqs))
	for i := range reqs {
		req := &reqs[i]
		if req.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("entry index %d: MCP server name is required", i),
			})
			return
		}
		if _, ok := resolvePriority(req.Priority); !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("entry index %d: priority must be between %d and %d", i, mcpPriorityMin, mcpPriorityMax),
			})
			return
		}
		if req.ID == "" {
			req.ID = generateID()
		}
		if prev, dup := seen[req.ID]; dup {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("duplicate id %q in request (indices %d and %d)", req.ID, prev, i),
			})
			return
		}
		seen[req.ID] = i
	}

	if h.crClient != nil {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			userID = "default-user"
		}
		h.createBulkMCPServerCR(c, reqs, userID)
		return
	}

	// Legacy path: in-memory store. Priority is ignored here (it only has
	// meaning on the CR's Status field); flat-MCPServer clients keep
	// working unchanged.
	servers := make([]*models.MCPServer, len(reqs))
	for i := range reqs {
		servers[i] = &reqs[i].MCPServer
	}
	if err := h.RegistryManager.UploadRegistryEntries(servers); err != nil {
		log.Printf("Error uploading MCP servers: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := map[string]interface{}{
		"message": fmt.Sprintf("Successfully uploaded %d MCP servers", len(servers)),
		"count":   len(servers),
	}

	log.Printf("Bulk uploaded %d MCP servers", len(servers))
	c.JSON(http.StatusOK, response)
}


// UploadLocalMCP handles POST /registry/upload/local-mcp
// @Summary Upload a local MCP server implementation
// @Description Upload Python scripts and configuration for a local STDIO MCP server
// @Tags registry
// @Accept multipart/form-data
// @Produce json
// @Param name formData string true "MCP server name"
// @Param description formData string false "MCP server description"
// @Param config formData string true "MCP client configuration JSON"
// @Param files formData []file true "Python script files and requirements.txt"
// @Success 201 {object} models.MCPServer
// @Failure 400 {string} string "Bad Request"
// @Router /api/v1/registry/upload/local-mcp [post]
func (h *RegistryHandler) UploadLocalMCP(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse multipart form"})
		return
	}

	params := registryadmin.LocalMCPParams{
		Name:        c.PostForm("name"),
		Description: c.PostForm("description"),
		Config:      c.PostForm("config"),
	}

	for _, fileHeader := range form.File["files"] {
		filename := fileHeader.Filename
		if !isValidMCPFile(filename) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid file type: %s", filename)})
			return
		}

		file, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
			return
		}

		content, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
			return
		}

		params.Files = append(params.Files, registryadmin.LocalMCPFile{Name: filename, Data: content})
	}

	server, err := h.AdminService.UploadLocalMCP(c.Request.Context(), params)
	if err != nil {
		log.Printf("Error uploading local MCP: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, server)
}

// isValidMCPFile validates that the file is a valid MCP-related file
func isValidMCPFile(filename string) bool {
	validExtensions := []string{".py", ".txt", ".md", ".json"}
	for _, ext := range validExtensions {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}
	return false
}

// generateID generates a unique ID for MCP servers
func generateID() string {
	return time.Now().Format("20060102150405") + fmt.Sprintf("%06d", time.Now().Nanosecond()/1000)
}
