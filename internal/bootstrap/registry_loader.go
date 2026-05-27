package bootstrap

// Bootstrap-time registry loader. This duplicates parseAndUploadRegistryYAML in
// internal/handlers/registry.go on purpose to keep issue #2 a pure extraction;
// issue #3 consolidates both copies into pkg/services/registry/loader.go.

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"suse-ai-up/internal/config"
	"suse-ai-up/internal/handlers"
	"suse-ai-up/pkg/models"
)

func parseAndUploadRegistryYAML(data []byte, registryManager *handlers.DefaultRegistryManager, source string) error {
	var servers []map[string]interface{}
	if err := yaml.Unmarshal(data, &servers); err != nil {
		return fmt.Errorf("could not parse registry YAML from %s: %w", source, err)
	}

	log.Printf("Loading %d MCP servers from %s", len(servers), source)

	var mcpServers []*models.MCPServer
	log.Printf("DEBUG: Processing %d servers from YAML", len(servers))
	for i, serverData := range servers {
		log.Printf("DEBUG: Server %d data: %+v", i, serverData)
		server := &models.MCPServer{}

		if name, ok := serverData["name"].(string); ok {
			server.ID = name
			server.Name = name
			log.Printf("DEBUG: Server name/ID: %s", name)
		} else {
			log.Printf("Warning: Server missing name field, skipping: %+v", serverData)
			continue
		}

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
			log.Printf("DEBUG: Loaded meta for server %s: %+v", server.Name, meta)
		} else {
			server.Meta = make(map[string]interface{})
			log.Printf("DEBUG: No meta field found for server %s", server.Name)
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

	log.Printf("DEBUG: Uploading %d MCP servers to registry", len(mcpServers))
	if err := registryManager.UploadRegistryEntries(mcpServers); err != nil {
		return fmt.Errorf("could not upload registry entries: %w", err)
	}
	log.Printf("DEBUG: Successfully uploaded MCP servers")

	return nil
}

func loadRegistryFromURL(registryManager *handlers.DefaultRegistryManager, url string, timeout time.Duration) error {
	log.Printf("Loading MCP registry from URL: %s", url)

	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(url)
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

	return parseAndUploadRegistryYAML(data, registryManager, url)
}

func loadRegistryFromFile(registryManager *handlers.DefaultRegistryManager, cfg *config.Config) {
	log.Printf("DEBUG: loadRegistryFromFile called")

	if err := registryManager.Clear(); err != nil {
		log.Printf("Warning: Failed to clear registry at startup: %v", err)
	}

	if cfg.MCPRegistryURL != "" {
		timeout, err := time.ParseDuration(cfg.RegistryTimeout)
		if err != nil {
			log.Printf("Warning: Invalid registry timeout %s, using 30s: %v", cfg.RegistryTimeout, err)
			timeout = 30 * time.Second
		}

		if err := loadRegistryFromURL(registryManager, cfg.MCPRegistryURL, timeout); err != nil {
			log.Printf("Warning: Failed to load registry from URL %s: %v, falling back to local file", cfg.MCPRegistryURL, err)
		} else {
			log.Printf("Successfully loaded MCP registry from URL: %s", cfg.MCPRegistryURL)
			return
		}
	}

	registryFile := "config/mcp_registry.yaml"
	data, err := os.ReadFile(registryFile)
	if err != nil {
		log.Printf("Warning: Could not read registry file %s: %v", registryFile, err)
		return
	}

	if err := parseAndUploadRegistryYAML(data, registryManager, registryFile); err != nil {
		log.Printf("Warning: Failed to parse and upload registry from file %s: %v", registryFile, err)
		return
	}

	log.Printf("Successfully loaded MCP registry from %s", registryFile)
}
