package router

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/SUSE/suse-ai-up/internal/bootstrap"
	"github.com/SUSE/suse-ai-up/pkg/auth"
	"github.com/SUSE/suse-ai-up/pkg/logging"
)

// Register installs CORS, /health, /docs and the full /api/v1 surface on r.
// It's a pure extraction from cmd/uniproxy/main.go's RunUniproxy; no behavior
// change.
func Register(r *gin.Engine, svc *bootstrap.AppServices) {
	// CORS middleware
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") || strings.Contains(origin, "192.168.") || strings.Contains(origin, "10.")) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, MCP-Protocol-Version, Mcp-Session-Id, X-User-Id, x-user-id")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// Swagger UI - relative URL for deployment compatibility
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/docs/doc.json")))

	// Helper: convert a stdlib http handler into a gin handler.
	ginToHTTPHandler := func(handler func(http.ResponseWriter, *http.Request)) gin.HandlerFunc {
		return func(c *gin.Context) {
			log.Printf("GIN HANDLER CALLED for path: %s", c.Request.URL.Path)
			handler(c.Writer, c.Request)
		}
	}

	logging.ProxyLogger.Info("Setting up API v1 routes")
	v1 := r.Group("/api/v1")
	logging.ProxyLogger.Info("V1 group created: %v", v1 != nil)
	{
		// Discovery routes
		discovery := v1.Group("/discovery")
		{
			discovery.POST("/scan", svc.DiscoveryHandler.ScanForMCPServers)
			discovery.GET("/scan", svc.DiscoveryHandler.ListScanJobs)
			discovery.GET("/scan/:jobId", svc.DiscoveryHandler.GetScanJob)
			discovery.DELETE("/scan/:jobId", svc.DiscoveryHandler.CancelScanJob)
			discovery.GET("/servers", svc.DiscoveryHandler.ListDiscoveredServers)
			discovery.GET("/servers/:id", svc.DiscoveryHandler.GetDeprecatedServer)
			discovery.GET("/results", svc.DiscoveryHandler.GetAllScanResults)
			discovery.GET("/results/:id", svc.DiscoveryHandler.GetServerFromResults)
		}

		// Adapter routes
		logging.ProxyLogger.Info("Setting up adapter routes")
		adapters := v1.Group("/adapters")
		{
			logging.ProxyLogger.Info("Adapter handler initialized: %v", svc.AdapterHandler != nil)
			logging.ProxyLogger.Info("Registering adapter GET route")
			adapters.GET("", ginToHTTPHandler(svc.AdapterHandler.ListAdapters))
			logging.ProxyLogger.Info("Registering adapter POST route")
			adapters.POST("", ginToHTTPHandler(svc.AdapterHandler.CreateAdapter))
			adapters.GET("/:name", ginToHTTPHandler(svc.AdapterHandler.GetAdapter))
			adapters.PUT("/:name", ginToHTTPHandler(svc.AdapterHandler.UpdateAdapter))
			adapters.DELETE("/:name", ginToHTTPHandler(svc.AdapterHandler.DeleteAdapter))
			adapters.POST("/:name/health", ginToHTTPHandler(svc.AdapterHandler.CheckAdapterHealth))

			// Token management
			adapters.GET("/:name/token", svc.TokenHandler.GetAdapterToken)
			adapters.POST("/:name/token/validate", svc.TokenHandler.ValidateToken)
			adapters.POST("/:name/token/refresh", svc.TokenHandler.RefreshToken)

			// Authentication
			adapters.GET("/:name/client-token", svc.MCPAuthHandler.GetClientToken)
			adapters.POST("/:name/validate-auth", svc.MCPAuthHandler.ValidateAuthConfig)
			adapters.POST("/:name/test-auth", svc.MCPAuthHandler.TestAuthConnection)

			// Adapter management
			adapters.GET("/:name/status", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"readyReplicas":     1,
					"updatedReplicas":   1,
					"availableReplicas": 1,
					"image":             "nginx:latest",
					"replicaStatus":     "Healthy",
				})
			})

			// MCP proxy endpoint - main integration point.
			// Wrapped in an auth.UserAuthMiddleware-protected sub-group so
			// only authenticated callers reach the proxy. The middleware
			// accepts X-Api-Token / Authorization: Bearer (and X-User-ID
			// in dev mode), then writes the resolved user ID into
			// X-User-ID on the request — HandleMCPProtocol still reads
			// X-User-ID unchanged.
			protectedMCP := adapters.Group("")
			protectedMCP.Use(auth.UserAuthMiddleware(svc.UserAuthService))
			{
				protectedMCP.Any("/:name/mcp", ginToHTTPHandler(svc.AdapterHandler.HandleMCPProtocol))
			}

			// Sync capabilities
			adapters.POST("/:name/sync", ginToHTTPHandler(svc.AdapterHandler.SyncAdapterCapabilities))

			// REST-style MCP endpoints
			adapters.GET("/:name/tools", func(c *gin.Context) {
				handleMCPToolsList(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
			adapters.POST("/:name/tools/:toolName/call", func(c *gin.Context) {
				handleMCPToolCall(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
			adapters.GET("/:name/resources", func(c *gin.Context) {
				handleMCPResourcesList(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
			adapters.GET("/:name/resources/*uri", func(c *gin.Context) {
				handleMCPResourceRead(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
			adapters.GET("/:name/prompts", func(c *gin.Context) {
				handleMCPPromptsList(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
			adapters.GET("/:name/prompts/:promptName", func(c *gin.Context) {
				handleMCPPromptGet(c, svc.AdapterStore, svc.StdioToHTTPAdapter, svc.RemoteHTTPPlugin, svc.SessionStore)
			})
		}

		// Registry routes
		registry := v1.Group("/registry")
		{
			registry.GET("", ginToHTTPHandler(svc.RegistryHandler.ListMCPServersFiltered))
			registry.POST("/upload", svc.RegistryHandler.UploadRegistryEntry)
			registry.POST("/upload/bulk", svc.RegistryHandler.UploadBulkRegistryEntries)
			registry.POST("/upload/git", svc.RegistryHandler.UploadGitRegistryFile)
			registry.POST("/upload/local-mcp", svc.RegistryHandler.UploadLocalMCP)
			registry.POST("/reload", svc.RegistryHandler.ReloadRegistry)
			registry.GET("/browse", svc.RegistryHandler.BrowseRegistry)

			registry.GET("/:id", svc.RegistryHandler.GetMCPServer)
			registry.PUT("/:id", svc.RegistryHandler.UpdateMCPServer)
			registry.DELETE("/:id", svc.RegistryHandler.DeleteMCPServer)
		}

		// Plugin routes
		pluginsGroup := v1.Group("/plugins")
		{
			pluginsGroup.POST("/register", svc.PluginHandler.RegisterService)
			pluginsGroup.DELETE("/register/:serviceId", svc.PluginHandler.UnregisterService)
			pluginsGroup.GET("/services", svc.PluginHandler.ListServices)
			pluginsGroup.GET("/services/:serviceId", svc.PluginHandler.GetService)
			pluginsGroup.GET("/services/type/:serviceType", svc.PluginHandler.ListServicesByType)
			pluginsGroup.GET("/services/:serviceId/health", svc.PluginHandler.GetServiceHealth)
		}

		// Authentication routes
		authRoutes := v1.Group("/auth")
		{
			authRoutes.POST("/login", svc.AuthHandler.Login)
			authRoutes.POST("/oauth/login", svc.AuthHandler.OAuthLogin)
			authRoutes.POST("/oauth/callback", svc.AuthHandler.OAuthCallback)
			authRoutes.PUT("/password", svc.AuthHandler.ChangePassword)
			authRoutes.POST("/logout", svc.AuthHandler.Logout)
		}

		// Unauthenticated auth mode endpoint (mounted on root, matches original)
		r.GET("/auth/mode", svc.AuthHandler.GetAuthMode)

		// User/Group management routes
		logging.ProxyLogger.Info("Registering user/group routes")
		users := v1.Group("/users")
		{
			logging.ProxyLogger.Info("Users group created: %v", users != nil)
			users.GET("", ginToHTTPHandler(svc.UserGroupHandler.ListUsers))
			users.GET("/:id", ginToHTTPHandler(svc.UserGroupHandler.GetUser))

			protectedUsers := users.Group("")
			protectedUsers.Use(auth.UserAuthMiddleware(svc.UserAuthService))
			{
				protectedUsers.POST("", ginToHTTPHandler(svc.UserGroupHandler.HandleUsers))
				protectedUsers.PUT("/:id", ginToHTTPHandler(svc.UserGroupHandler.UpdateUser))
				protectedUsers.DELETE("/:id", ginToHTTPHandler(svc.UserGroupHandler.DeleteUser))
			}
		}

		groups := v1.Group("/groups")
		{
			groups.GET("", ginToHTTPHandler(svc.UserGroupHandler.HandleGroups))
			groups.GET("/:id", ginToHTTPHandler(svc.UserGroupHandler.GetGroup))

			protectedGroups := groups.Group("")
			protectedGroups.Use(auth.UserAuthMiddleware(svc.UserAuthService))
			{
				protectedGroups.POST("", ginToHTTPHandler(svc.UserGroupHandler.HandleGroups))
				protectedGroups.PUT("/:id", ginToHTTPHandler(svc.UserGroupHandler.UpdateGroup))
				protectedGroups.DELETE("/:id", ginToHTTPHandler(svc.UserGroupHandler.DeleteGroup))
				protectedGroups.POST("/:id/members", ginToHTTPHandler(svc.UserGroupHandler.AddUserToGroup))
				protectedGroups.DELETE("/:id/members/:userId", ginToHTTPHandler(svc.UserGroupHandler.RemoveUserFromGroup))
			}
		}

		// Route assignment routes (under registry)
		registry.POST("/:id/routes", ginToHTTPHandler(svc.RouteAssignmentHandler.CreateRouteAssignment))
		registry.GET("/:id/routes", ginToHTTPHandler(svc.RouteAssignmentHandler.ListRouteAssignments))
		registry.PUT("/:id/routes/:assignmentId", ginToHTTPHandler(svc.RouteAssignmentHandler.UpdateRouteAssignment))
		registry.DELETE("/:id/routes/:assignmentId", ginToHTTPHandler(svc.RouteAssignmentHandler.DeleteRouteAssignment))
	}
}
