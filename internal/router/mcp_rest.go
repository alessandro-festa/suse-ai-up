package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/mcp"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/proxy"
	"suse-ai-up/pkg/session"
)

// makeMCPRequestWithSession establishes MCP session and makes request
func makeMCPRequestWithSession(ctx context.Context, mcpURL string, request mcp.MCPMessage, auth *models.AdapterAuthConfig) (*http.Response, error) {
	fmt.Printf("DEBUG: Starting MCP session establishment for URL: %s\n", mcpURL)

	initRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "suse-ai-up-rest-api",
				"version": "1.0.0",
			},
		},
	}

	fmt.Printf("DEBUG: Sending initialize request\n")
	initResp, err := makeRawMCPRequest(ctx, mcpURL, initRequest, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MCP session: %w", err)
	}
	defer initResp.Body.Close()

	initBody, err := io.ReadAll(initResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read initialize response: %w", err)
	}

	if initResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("initialize failed with status %d: %s", initResp.StatusCode, string(initBody))
	}

	fmt.Printf("DEBUG: Initialize response received: %s\n", string(initBody))

	responseBody := string(initBody)
	var jsonData string

	if strings.Contains(responseBody, "event: message\ndata: ") {
		lines := strings.Split(responseBody, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "data: ") {
				jsonData = strings.TrimPrefix(line, "data: ")
				break
			}
		}
	} else {
		jsonData = responseBody
	}

	fmt.Printf("DEBUG: Extracted JSON data: %s\n", jsonData)

	var initResult map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &initResult); err != nil {
		return nil, fmt.Errorf("failed to parse initialize response: %w", err)
	}

	sessionID := "rest-api-session"
	if result, ok := initResult["result"].(map[string]interface{}); ok {
		if serverInfo, ok := result["serverInfo"].(map[string]interface{}); ok {
			if name, ok := serverInfo["name"].(string); ok {
				sessionID = fmt.Sprintf("rest-api-%s", name)
			}
		}
	}

	fmt.Printf("DEBUG: Using session ID: %s\n", sessionID)

	initializedRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]interface{}{},
	}

	fmt.Printf("DEBUG: Sending initialized notification\n")
	initializedResp, err := makeRawMCPRequestWithSession(ctx, mcpURL, initializedRequest, auth, sessionID)
	if err != nil {
		fmt.Printf("Warning: initialized notification failed: %v\n", err)
	} else {
		fmt.Printf("DEBUG: Initialized notification sent successfully\n")
	}

	if initializedResp != nil {
		initializedResp.Body.Close()
	}

	fmt.Printf("DEBUG: Making main request with session ID: %s\n", sessionID)
	return makeRawMCPRequestWithSession(ctx, mcpURL, request, auth, sessionID)
}

func makeRawMCPRequest(ctx context.Context, mcpURL string, request mcp.MCPMessage, auth *models.AdapterAuthConfig) (*http.Response, error) {
	return makeRawMCPRequestWithSession(ctx, mcpURL, request, auth, "")
}

func makeRawMCPRequestWithSession(ctx context.Context, mcpURL string, request mcp.MCPMessage, auth *models.AdapterAuthConfig, sessionID string) (*http.Response, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", mcpURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	if sessionID != "" {
		req.Header.Set("mcp-session-id", sessionID)
		values := url.Values{}
		values.Set("sessionId", sessionID)
		req.URL.RawQuery = values.Encode()
	}

	if auth != nil && auth.BearerToken != nil && auth.BearerToken.Token != "" {
		req.Header.Set("Authorization", "Bearer "+auth.BearerToken.Token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// handleMCPToolsList handles GET /adapters/{name}/tools - REST-style tools/list
// @Summary List MCP tools
// @Description Get the list of tools available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with tools list"
// @Failure 404 {object} handlers.ErrorResponse "Adapter not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/tools [get]
func handleMCPToolsList(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	toolsListRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	fmt.Printf("REST_API_DEBUG: About to call makeMCPRequestWithSession for adapter %s, URL: %s\n", adapter.Name, adapter.URL)
	resp, err := makeMCPRequestWithSession(c.Request.Context(), adapter.URL, toolsListRequest, adapter.Authentication)
	fmt.Printf("REST_API_DEBUG: makeMCPRequestWithSession returned, err: %v\n", err)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("MCP request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	c.Data(http.StatusOK, "application/json", body)
}

// handleMCPToolCall handles POST /adapters/{name}/tools/{toolName}/call - REST-style tools/call
// @Summary Call MCP tool
// @Description Execute a specific MCP tool with given arguments
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Param toolName path string true "Tool name"
// @Param request body mcp.MCPMessage true "Tool call request with arguments"
// @Success 200 {object} map[string]interface{} "MCP response with tool result"
// @Failure 404 {object} handlers.ErrorResponse "Adapter or tool not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 400 {object} handlers.ErrorResponse "Invalid request parameters"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/tools/{toolName}/call [post]
func handleMCPToolCall(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")
	toolName := c.Param("toolName")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	var requestBody map[string]interface{}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	toolCallRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": requestBody,
		},
	}

	jsonRequestBody, err := json.Marshal(toolCallRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(jsonRequestBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Stdio adapter error: %v", err)})
			return
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, sessionStore); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Remote HTTP plugin error: %v", err)})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
		return
	}
}

// handleMCPResourcesList handles GET /adapters/{name}/resources - REST-style resources/list
// @Summary List MCP resources
// @Description Get the list of resources available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with resources list"
// @Failure 404 {object} handlers.ErrorResponse "Adapter not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/resources [get]
func handleMCPResourcesList(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	resourcesListRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "resources/list",
		Params:  map[string]interface{}{},
	}

	requestBody, err := json.Marshal(resourcesListRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(requestBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Stdio adapter error: %v", err)})
			return
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, sessionStore); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Remote HTTP plugin error: %v", err)})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
		return
	}
}

// handleMCPResourceRead handles GET /adapters/{name}/resources/*uri - REST-style resources/read
// @Summary Read MCP resource
// @Description Read the content of a specific MCP resource by URI
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Param uri path string true "Resource URI"
// @Success 200 {object} map[string]interface{} "MCP response with resource content"
// @Failure 404 {object} handlers.ErrorResponse "Adapter or resource not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/resources/{uri} [get]
func handleMCPResourceRead(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")
	resourceURI := c.Param("uri")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	resourceReadRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "resources/read",
		Params: map[string]interface{}{
			"uri": resourceURI,
		},
	}

	requestBody, err := json.Marshal(resourceReadRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(requestBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Stdio adapter error: %v", err)})
			return
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, sessionStore); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Remote HTTP plugin error: %v", err)})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
		return
	}
}

// handleMCPPromptsList handles GET /adapters/{name}/prompts - REST-style prompts/list
// @Summary List MCP prompts
// @Description Get the list of prompts available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with prompts list"
// @Failure 404 {object} handlers.ErrorResponse "Adapter not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/prompts [get]
func handleMCPPromptsList(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	promptsListRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "prompts/list",
		Params:  map[string]interface{}{},
	}

	requestBody, err := json.Marshal(promptsListRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(requestBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Stdio adapter error: %v", err)})
			return
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, sessionStore); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Remote HTTP plugin error: %v", err)})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
		return
	}
}

// handleMCPPromptGet handles GET /adapters/{name}/prompts/{promptName} - REST-style prompts/get
// @Summary Get MCP prompt
// @Description Get the content of a specific MCP prompt by name
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param X-User-ID header string false "User ID" default(default-user)
// @Param name path string true "Adapter ID"
// @Param promptName path string true "Prompt name"
// @Success 200 {object} map[string]interface{} "MCP response with prompt content"
// @Failure 404 {object} handlers.ErrorResponse "Adapter or prompt not found"
// @Failure 401 {object} handlers.ErrorResponse "Authentication required"
// @Failure 500 {object} handlers.ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/prompts/{promptName} [get]
func handleMCPPromptGet(c *gin.Context, adapterStore clients.AdapterResourceStore, stdioToHTTPAdapter *proxy.StdioToHTTPAdapter, remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin, sessionStore session.SessionStore) {
	adapterName := c.Param("name")
	promptName := c.Param("promptName")

	adapter, err := adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuthentication(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return
		}
	}

	args := make(map[string]interface{})
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			args[key] = values[0]
		}
	}

	promptGetRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "prompts/get",
		Params: map[string]interface{}{
			"name":      promptName,
			"arguments": args,
		},
	}

	requestBody, err := json.Marshal(promptGetRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(requestBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Stdio adapter error: %v", err)})
			return
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, sessionStore); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Remote HTTP plugin error: %v", err)})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
		return
	}
}

// validateClientAuthentication validates client authentication for adapter access
func validateClientAuthentication(c *gin.Context, auth *models.AdapterAuthConfig) error {
	if auth == nil || !auth.Required {
		return nil
	}

	switch auth.Type {
	case "bearer":
		return validateBearerAuth(c, auth)
	case "basic":
		return validateBasicAuth(c, auth)
	case "apikey":
		return validateAPIKeyAuth(c, auth)
	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}
}

func validateBearerAuth(c *gin.Context, auth *models.AdapterAuthConfig) error {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	var expectedToken string

	if auth.BearerToken != nil && auth.BearerToken.Token != "" {
		expectedToken = auth.BearerToken.Token
	}

	if token != expectedToken {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func validateBasicAuth(c *gin.Context, auth *models.AdapterAuthConfig) error {
	if auth.Basic == nil {
		return fmt.Errorf("basic authentication configuration not found")
	}

	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return fmt.Errorf("missing or invalid Basic authentication header")
	}

	if username != auth.Basic.Username || password != auth.Basic.Password {
		return fmt.Errorf("invalid username or password")
	}

	return nil
}

func validateAPIKeyAuth(c *gin.Context, auth *models.AdapterAuthConfig) error {
	if auth.APIKey == nil {
		return fmt.Errorf("API key configuration not found")
	}

	location := strings.ToLower(auth.APIKey.Location)
	name := auth.APIKey.Name
	expectedKey := auth.APIKey.Key

	var providedKey string
	var found bool

	switch location {
	case "header":
		providedKey = c.GetHeader(name)
		found = providedKey != ""
	case "query":
		providedKey = c.Query(name)
		found = providedKey != ""
	case "cookie":
		cookie, err := c.Cookie(name)
		if err == nil {
			providedKey = cookie
			found = true
		}
	default:
		return fmt.Errorf("unsupported API key location: %s", location)
	}

	if !found {
		return fmt.Errorf("API key not found in %s '%s'", location, name)
	}

	if providedKey != expectedKey {
		return fmt.Errorf("invalid API key")
	}

	return nil
}
