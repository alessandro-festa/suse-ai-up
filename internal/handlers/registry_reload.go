package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ReloadRegistry handles POST /registry/reload
// @Summary Reload registry from configured source
// @Description Reload MCP server registry from URL or local file based on configuration
// @Tags registry
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {string} string "Internal Server Error"
// @Router /api/v1/registry/reload [post]
func (h *RegistryHandler) ReloadRegistry(c *gin.Context) {
	result, err := h.AdminService.ReloadFromConfig(c.Request.Context())
	if err != nil {
		log.Printf("Error reloading registry: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"message":     "Registry reloaded successfully",
		"source":      result.Source,
		"serverCount": result.ServerCount,
	})
}
