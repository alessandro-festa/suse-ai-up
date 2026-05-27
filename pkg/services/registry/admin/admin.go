// Package admin contains operational/administrative registry tasks that the
// HTTP handler delegates to: reloading the registry from its configured
// source, persisting registry contents to a Kubernetes ConfigMap, and
// accepting locally-uploaded MCP server bundles. This lives in a sub-package
// to avoid the import cycle that exists between
// pkg/services/registry (top-level) and internal/handlers.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"suse-ai-up/internal/config"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/services/registry/loader"
)

const defaultRegistryTimeout = 30 * time.Second

// Service performs registry-administration work on behalf of HTTP handlers.
// It depends only on the loader's Store/Manager interfaces and the typed
// Kubernetes client, so it can be exercised without spinning up the HTTP
// layer.
type Service struct {
	store     loader.Store
	regMgr    loader.Manager
	k8sClient kubernetes.Interface
	cfg       *config.Config
}

// NewService wires the dependencies the admin service needs. k8sClient may
// be nil when running outside a cluster — ConfigMap updates become no-ops.
func NewService(store loader.Store, regMgr loader.Manager, k8sClient kubernetes.Interface, cfg *config.Config) *Service {
	return &Service{
		store:     store,
		regMgr:    regMgr,
		k8sClient: k8sClient,
		cfg:       cfg,
	}
}

// ReloadResult describes a completed reload so the HTTP layer can render its
// response without re-deriving the values.
type ReloadResult struct {
	Source      string
	ServerCount int
}

// ReloadFromConfig replicates the HTTP handler's URL-first, file-fallback
// reload flow. On URL success it also persists the fetched bytes back to the
// registry ConfigMap. On URL failure (or when no URL is configured) it falls
// back to the default on-disk registry file.
func (s *Service) ReloadFromConfig(ctx context.Context) (ReloadResult, error) {
	log.Printf("Reloading MCP registry")

	var (
		source      string
		serverCount int
		err         error
	)

	if s.cfg.MCPRegistryURL != "" {
		timeout, parseErr := time.ParseDuration(s.cfg.RegistryTimeout)
		if parseErr != nil {
			log.Printf("Warning: Invalid registry timeout %s, using 30s: %v", s.cfg.RegistryTimeout, parseErr)
			timeout = defaultRegistryTimeout
		}

		source = s.cfg.MCPRegistryURL

		client := &http.Client{Timeout: timeout}

		resp, httpErr := client.Get(source)
		if httpErr != nil {
			err = fmt.Errorf("failed to fetch from URL %s: %w", source, httpErr)
		} else {
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("URL returned status %d", resp.StatusCode)
			} else {
				data, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					err = fmt.Errorf("failed to read response body: %w", readErr)
				} else {
					var servers []map[string]interface{}
					if parseErr := json.Unmarshal(data, &servers); parseErr != nil {
						servers = nil
						if yamlErr := yaml.Unmarshal(data, &servers); yamlErr != nil {
							err = fmt.Errorf("could not parse registry data from %s as JSON or YAML: %w", source, yamlErr)
						}
					}

					if err == nil {
						log.Printf("Loading %d MCP servers from %s", len(servers), source)
						mcpServers := make([]*models.MCPServer, 0, len(servers))

						for _, serverData := range servers {
							server := &models.MCPServer{}

							if name, ok := serverData["name"].(string); ok {
								server.ID = name
								server.Name = name
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
							if configField, ok := serverData["config"].(map[string]interface{}); ok {
								server.Meta["config"] = configField
							}
							if serverType, ok := serverData["type"].(string); ok {
								server.Meta["type"] = serverType
							}

							mcpServers = append(mcpServers, server)
						}

						if clearErr := s.regMgr.Clear(); clearErr != nil {
							log.Printf("Warning: Failed to clear registry before reload: %v", clearErr)
						}

						if uploadErr := s.regMgr.UploadRegistryEntries(mcpServers); uploadErr != nil {
							err = fmt.Errorf("could not upload registry entries: %w", uploadErr)
						} else {
							serverCount = len(mcpServers)

							if updateErr := s.UpdateConfigMap(ctx, data); updateErr != nil {
								log.Printf("Warning: Failed to update registry ConfigMap: %v", updateErr)
							}
						}
					}
				}
			}
		}
	}

	if source == "" || err != nil {
		source = loader.DefaultRegistryFile
		log.Printf("Loading MCP registry from local file: %s", source)

		data, readErr := os.ReadFile(source)
		if readErr != nil {
			err = fmt.Errorf("failed to read local file %s: %w", source, readErr)
		} else {
			if parseErr := loader.ParseAndUploadRegistryYAML(data, s.regMgr, source); parseErr != nil {
				err = fmt.Errorf("failed to parse local file %s: %w", source, parseErr)
			} else {
				serverCount = len(s.store.ListMCPServers())
				err = nil
			}
		}
	}

	if err != nil {
		return ReloadResult{}, err
	}

	log.Printf("Registry reloaded from %s with %d servers", source, serverCount)
	return ReloadResult{Source: source, ServerCount: serverCount}, nil
}

// UpdateConfigMap writes the raw registry YAML to the cluster ConfigMap that
// backs registry persistence. Namespace and ConfigMap name come from
// environment variables, falling back to the same defaults the HTTP handler
// used. When no Kubernetes client is configured this is a no-op.
func (s *Service) UpdateConfigMap(ctx context.Context, registryData []byte) error {
	if s.k8sClient == nil {
		return nil
	}

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			namespace = string(data)
		} else {
			namespace = os.Getenv("POD_NAMESPACE")
			if namespace == "" {
				namespace = "default"
			}
		}
	}

	configMapName := os.Getenv("REGISTRY_CONFIGMAP_NAME")
	if configMapName == "" {
		deploymentName := os.Getenv("DEPLOYMENT_NAME")
		if deploymentName == "" {
			deploymentName = os.Getenv("HOSTNAME")
			if deploymentName == "" {
				deploymentName = "suse-ai-up"
			}
		}
		configMapName = deploymentName + "-registry"
	}

	configMap, err := s.k8sClient.CoreV1().ConfigMaps(namespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		log.Printf("Warning: Failed to get ConfigMap %s/%s: %v", namespace, configMapName, err)
		return fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	configMap.Data["mcp_registry.yaml"] = string(registryData)

	if _, err := s.k8sClient.CoreV1().ConfigMaps(namespace).Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
		log.Printf("Warning: Failed to update ConfigMap %s/%s: %v", namespace, configMapName, err)
		return fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	log.Printf("Successfully updated ConfigMap %s/%s with new registry data", namespace, configMapName)
	return nil
}

// LocalMCPFile is one uploaded file's contents and filename. The HTTP layer
// reads multipart bodies and passes them in via LocalMCPParams.
type LocalMCPFile struct {
	Name string
	Data []byte
}

// LocalMCPParams carries the form fields the local-MCP upload endpoint
// accepts. The handler owns multipart parsing; the service owns validation
// and persistence.
type LocalMCPParams struct {
	Name        string
	Description string
	Config      string
	Files       []LocalMCPFile
}

// UploadLocalMCP validates a local-MCP submission, constructs an MCPServer
// entry with the parsed client config and uploaded files attached, and
// stores it. Returns the stored server on success.
func (s *Service) UploadLocalMCP(ctx context.Context, p LocalMCPParams) (*models.MCPServer, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if p.Config == "" {
		return nil, fmt.Errorf("config is required")
	}

	var mcpConfig models.MCPClientConfig
	if err := json.Unmarshal([]byte(p.Config), &mcpConfig); err != nil {
		return nil, fmt.Errorf("invalid MCP client configuration JSON: %w", err)
	}

	if len(mcpConfig.MCPServers) == 0 {
		return nil, fmt.Errorf("MCP client config must contain at least one server")
	}

	if len(p.Files) == 0 {
		return nil, fmt.Errorf("at least one file must be uploaded")
	}

	fileContents := make(map[string][]byte, len(p.Files))
	for _, f := range p.Files {
		fileContents[f.Name] = f.Data
	}

	serverID := generateID()
	server := &models.MCPServer{
		ID:               serverID,
		Name:             p.Name,
		Description:      p.Description,
		ValidationStatus: "uploaded",
		DiscoveredAt:     time.Now(),
		Meta: map[string]interface{}{
			"isLocalMCP":      true,
			"mcpClientConfig": mcpConfig,
			"uploadedFiles":   fileContents,
		},
	}

	for serverName := range mcpConfig.MCPServers {
		server.Packages = []models.Package{
			{
				RegistryType: "local",
				Identifier:   serverName,
				Transport: models.Transport{
					Type: "stdio",
				},
			},
		}
		break
	}

	if err := s.store.CreateMCPServer(server); err != nil {
		return nil, fmt.Errorf("failed to store MCP server: %w", err)
	}

	_ = ctx
	log.Printf("Uploaded local MCP server: %s", serverID)
	return server, nil
}

func generateID() string {
	return time.Now().Format("20060102150405") + fmt.Sprintf("%06d", time.Now().Nanosecond()/1000)
}
