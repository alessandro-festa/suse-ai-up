/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// UploadGitRegistryFile fetches a registry YAML document from a Git host
// (GitHub / GitLab / raw URL / generic), parses it as a list of MCP server
// entries, and bulk-uploads them through the same createBulkMCPServerCR
// path used by POST /api/v1/registry/upload/bulk — so CR creation,
// priority stamping, and rollback-on-failure all behave identically.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

const gitFetchTimeout = 30 * time.Second

// GitRegistryUploadRequest is the wire shape for POST /api/v1/registry/upload/git.
type GitRegistryUploadRequest struct {
	// URL is required. Accepted forms:
	//   - https://github.com/<owner>/<repo>  → combined with Path (and optional Branch)
	//   - https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>
	//   - https://gitlab.com/<group>/<project>/-/raw/<branch>/<path>
	//   - any other https:// URL that returns the YAML body directly
	URL string `json:"url"`

	// Token is optional. For private repos:
	//   - github.com / raw.githubusercontent.com → sent as Authorization: Bearer <Token>
	//   - gitlab.com (api.gitlab.com)            → sent as PRIVATE-TOKEN: <Token>
	//   - other hosts                            → sent as Authorization: Bearer <Token>
	Token string `json:"token,omitempty"`

	// Branch is only used when URL points at a github.com repo root and the
	// caller didn't bake the ref into the path. Defaults to "main".
	Branch string `json:"branch,omitempty"`

	// Path is only used when URL points at a github.com repo root.
	// Example: "hack/registry/mcp_registry.yaml".
	Path string `json:"path,omitempty"`
}

// UploadGitRegistryFile handles POST /api/v1/registry/upload/git.
//
// @Summary Bulk-upload a registry YAML hosted on a git host
// @Description Fetch a YAML document (single doc, list of entries) from a git
// host and create one MCPServer CR per entry. Atomic: any failure rolls back
// previously-created CRs from the same batch.
// @Tags registry
// @Accept json
// @Produce json
// @Param body body GitRegistryUploadRequest true "Git source descriptor"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 502 {object} map[string]string
// @Router /api/v1/registry/upload/git [post]
func (h *RegistryHandler) UploadGitRegistryFile(c *gin.Context) {
	var req GitRegistryUploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}

	if h.crClient == nil {
		// Git upload is CR-only because it reuses createBulkMCPServerCR.
		// Legacy in-memory store path isn't supported (no need — the
		// operator is always running when this surface is exposed).
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "git registry upload requires the operator manager"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), gitFetchTimeout)
	defer cancel()

	data, err := fetchGitYAML(ctx, req)
	if err != nil {
		log.Printf("UploadGitRegistryFile fetch error from %s: %v", req.URL, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch failed: " + err.Error()})
		return
	}

	reqs, parseErr := parseRegistryYAMLToBulk(data)
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": parseErr.Error()})
		return
	}
	if len(reqs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no MCP server entries found in YAML"})
		return
	}

	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		userID = "default-user"
	}

	h.createBulkMCPServerCR(c, reqs, userID)
}

// fetchGitYAML chooses a fetch strategy based on the URL host so private
// repos work via the host's native auth scheme without forcing the caller
// to know each provider's URL conventions.
func fetchGitYAML(ctx context.Context, req GitRegistryUploadRequest) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid url")
	}

	host := strings.ToLower(parsed.Host)
	switch {
	case host == "github.com":
		return fetchFromGitHubRepoRoot(ctx, parsed, req.Path, req.Branch, req.Token)
	case host == "raw.githubusercontent.com":
		return doGet(ctx, parsed.String(), githubAuthHeaders(req.Token))
	case strings.HasSuffix(host, "gitlab.com"):
		return doGet(ctx, parsed.String(), gitlabAuthHeaders(req.Token))
	default:
		return doGet(ctx, parsed.String(), bearerAuthHeaders(req.Token))
	}
}

// fetchFromGitHubRepoRoot handles `https://github.com/<owner>/<repo>` URLs
// by translating into the GitHub Contents API, which works for both public
// and private repos provided the token has the right scope.
func fetchFromGitHubRepoRoot(ctx context.Context, u *url.URL, path, branch, token string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required for github.com/<owner>/<repo> URLs (e.g. hack/registry/mcp_registry.yaml)")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("github.com URL must include owner and repo: %s", u.String())
	}
	owner, repo := parts[0], parts[1]

	api := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s",
		url.PathEscape(owner), url.PathEscape(repo), strings.TrimPrefix(path, "/"))
	if branch != "" {
		api += "?ref=" + url.QueryEscape(branch)
	}

	headers := githubAuthHeaders(token)
	headers["Accept"] = "application/vnd.github+json"

	body, err := doGet(ctx, api, headers)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding github contents api response: %w", err)
	}
	if strings.ToLower(resp.Encoding) != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q from github contents api", resp.Encoding)
	}
	// GitHub wraps base64 with newlines per RFC 2045.
	cleaned := strings.ReplaceAll(resp.Content, "\n", "")
	data, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("base64-decoding github content: %w", err)
	}
	return data, nil
}

func githubAuthHeaders(token string) map[string]string {
	if token == "" {
		return map[string]string{}
	}
	return map[string]string{"Authorization": "Bearer " + token}
}

func gitlabAuthHeaders(token string) map[string]string {
	if token == "" {
		return map[string]string{}
	}
	return map[string]string{"PRIVATE-TOKEN": token}
}

func bearerAuthHeaders(token string) map[string]string {
	if token == "" {
		return map[string]string{}
	}
	return map[string]string{"Authorization": "Bearer " + token}
}

func doGet(ctx context.Context, target string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Same shape as pkg/services/registry/sync_manager.go and loader.go.
	client := &http.Client{Timeout: gitFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %d %s", target, resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// parseRegistryYAMLToBulk projects a YAML registry document into the same
// []UploadRegistryEntryRequest shape that POST /api/v1/registry/upload/bulk
// already accepts. Mapping follows pkg/services/registry/loader/loader.go's
// ParseAndUploadRegistryYAML so file uploads and YAML loaded at startup
// produce identical CRs.
func parseRegistryYAMLToBulk(data []byte) ([]UploadRegistryEntryRequest, error) {
	var entries []map[string]interface{}
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("could not parse registry YAML: %w", err)
	}
	out := make([]UploadRegistryEntryRequest, 0, len(entries))
	for _, raw := range entries {
		name, _ := raw["name"].(string)
		if name == "" {
			continue
		}
		server := models.MCPServer{ID: name, Name: name}
		if desc, ok := raw["description"].(string); ok {
			server.Description = desc
		}
		if image, ok := raw["image"].(string); ok {
			server.Packages = []models.Package{{
				Identifier: image,
				Transport:  models.Transport{Type: "stdio"},
			}}
		}
		meta := map[string]interface{}{}
		if m, ok := raw["meta"].(map[string]interface{}); ok {
			for k, v := range m {
				meta[k] = v
			}
		}
		if about, ok := raw["about"].(map[string]interface{}); ok {
			meta["about"] = about
		}
		if src, ok := raw["source"].(map[string]interface{}); ok {
			meta["source"] = src
		}
		if cfg, ok := raw["config"].(map[string]interface{}); ok {
			meta["config"] = cfg
		}
		if t, ok := raw["type"].(string); ok {
			meta["type"] = t
		}
		server.Meta = meta
		out = append(out, UploadRegistryEntryRequest{MCPServer: server})
	}
	return out, nil
}
