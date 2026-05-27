package loader

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// DefaultRegistryFile is the on-disk fallback used when no registry URL is configured
// or when the URL fetch fails.
const DefaultRegistryFile = "config/mcp_registry.yaml"

const defaultRegistryTimeout = 30 * time.Second

// Manager is the minimal surface the loader needs from a registry manager.
// Defined here so this package depends on nothing in internal/handlers.
type Manager interface {
	UploadRegistryEntries(entries []*models.MCPServer) error
	Clear() error
}

// Store is the minimal MCP server storage surface used by callers that need
// to list, create, or look up servers (e.g. the admin reload/upload flows).
type Store interface {
	ListMCPServers() []*models.MCPServer
	CreateMCPServer(server *models.MCPServer) error
	GetMCPServer(id string) (*models.MCPServer, error)
}

// ParseAndUploadRegistryYAML parses a registry YAML payload and uploads each
// entry through mgr. source is used only in log messages.
func ParseAndUploadRegistryYAML(data []byte, mgr Manager, source string) error {
	var servers []map[string]interface{}
	if err := yaml.Unmarshal(data, &servers); err != nil {
		return fmt.Errorf("could not parse registry YAML from %s: %w", source, err)
	}

	log.Printf("Loading %d MCP servers from %s", len(servers), source)

	mcpServers := make([]*models.MCPServer, 0, len(servers))
	for _, serverData := range servers {
		server := &models.MCPServer{}

		name, ok := serverData["name"].(string)
		if !ok {
			log.Printf("Warning: Server missing name field, skipping: %+v", serverData)
			continue
		}
		server.ID = name
		server.Name = name

		if desc, ok := serverData["description"].(string); ok {
			server.Description = desc
		}

		if image, ok := serverData["image"].(string); ok {
			server.Packages = []models.Package{
				{
					Identifier: image,
					Transport: models.Transport{
						Type: "stdio",
					},
				},
			}
		}

		if meta, ok := serverData["meta"].(map[string]interface{}); ok {
			server.Meta = meta
		} else {
			server.Meta = make(map[string]interface{})
		}

		server.Meta["source"] = "yaml"

		if about, ok := serverData["about"].(map[string]interface{}); ok {
			server.Meta["about"] = about
		}
		if sourceInfo, ok := serverData["source"].(map[string]interface{}); ok {
			server.Meta["source_info"] = sourceInfo
		}
		if cfg, ok := serverData["config"].(map[string]interface{}); ok {
			server.Meta["config"] = cfg
		}
		if serverType, ok := serverData["type"].(string); ok {
			server.Meta["type"] = serverType
		}

		mcpServers = append(mcpServers, server)
	}

	if err := mgr.UploadRegistryEntries(mcpServers); err != nil {
		return fmt.Errorf("could not upload registry entries: %w", err)
	}

	return nil
}

// LoadInitialRegistry resolves the registry source from cfg (URL first, file
// fallback) and uploads it through mgr. It clears mgr before loading. Missing
// config is not an error: if neither URL nor fallback file is available the
// function logs and returns nil.
func LoadInitialRegistry(ctx context.Context, mgr Manager, cfg *config.Config) error {
	if err := mgr.Clear(); err != nil {
		log.Printf("Warning: Failed to clear registry at startup: %v", err)
	}

	if cfg.MCPRegistryURL != "" {
		timeout, err := time.ParseDuration(cfg.RegistryTimeout)
		if err != nil {
			log.Printf("Warning: Invalid registry timeout %s, using %s: %v", cfg.RegistryTimeout, defaultRegistryTimeout, err)
			timeout = defaultRegistryTimeout
		}

		if err := loadRegistryFromURL(ctx, mgr, cfg.MCPRegistryURL, timeout); err != nil {
			log.Printf("Warning: Failed to load registry from URL %s: %v, falling back to local file", cfg.MCPRegistryURL, err)
		} else {
			log.Printf("Successfully loaded MCP registry from URL: %s", cfg.MCPRegistryURL)
			return nil
		}
	}

	data, err := os.ReadFile(DefaultRegistryFile)
	if err != nil {
		log.Printf("Warning: Could not read registry file %s: %v", DefaultRegistryFile, err)
		return nil
	}

	if err := ParseAndUploadRegistryYAML(data, mgr, DefaultRegistryFile); err != nil {
		log.Printf("Warning: Failed to parse and upload registry from file %s: %v", DefaultRegistryFile, err)
		return nil
	}

	log.Printf("Successfully loaded MCP registry from %s", DefaultRegistryFile)
	return nil
}

func loadRegistryFromURL(ctx context.Context, mgr Manager, url string, timeout time.Duration) error {
	log.Printf("Loading MCP registry from URL: %s", url)

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to build request for %s: %w", url, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch from URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("URL returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return ParseAndUploadRegistryYAML(data, mgr, url)
}
