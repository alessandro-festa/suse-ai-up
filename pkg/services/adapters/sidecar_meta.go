package services

import (
	"fmt"
	"strings"

	"github.com/SUSE/suse-ai-up/pkg/models"
)

// getSidecarConfig extracts the complete sidecar configuration from server metadata
func (as *AdapterService) getSidecarConfig(server *models.MCPServer) *models.SidecarConfig {
	fmt.Printf("ADAPTER_SERVICE_DEBUG: getSidecarConfig called for server %s\n", server.Name)

	if server.Meta == nil {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: server.Meta is nil\n")
		return nil
	}

	sidecarConfigRaw, ok := server.Meta["sidecarConfig"]
	if !ok {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: sidecarConfig not found in meta\n")
		return nil
	}

	configMap, ok := sidecarConfigRaw.(map[string]interface{})
	if !ok {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: sidecarConfig is not a map, type: %T, value: %v\n", sidecarConfigRaw, sidecarConfigRaw)
		return nil
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: sidecarConfig keys: %v\n", getMapKeys(configMap))

	commandType, ok := configMap["commandType"].(string)
	if !ok || commandType == "" {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: commandType not found or empty\n")
		return nil
	}

	command, ok := configMap["command"].(string)
	if !ok || command == "" {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: command not found or empty\n")
		return nil
	}

	port := 8000 // Default port
	if portRaw, ok := configMap["port"]; ok {
		if portFloat, ok := portRaw.(float64); ok {
			port = int(portFloat)
		}
	}

	sidecarConfig := &models.SidecarConfig{
		CommandType: commandType,
		Command:     command,
		Port:        port,
	}

	// Extract source and lastUpdated if available
	if source, ok := configMap["source"].(string); ok {
		sidecarConfig.Source = source
	}
	if lastUpdated, ok := configMap["lastUpdated"].(string); ok {
		sidecarConfig.LastUpdated = lastUpdated
	}

	// Extract project URL and release URL from server source_info metadata
	// The source information is stored in Meta["source_info"] during YAML parsing
	if sourceInfo, ok := server.Meta["source_info"]; ok {
		if sourceMap, ok := sourceInfo.(map[string]interface{}); ok {
			if project, ok := sourceMap["project"].(string); ok && project != "" {
				sidecarConfig.ProjectURL = project
				fmt.Printf("ADAPTER_SERVICE_DEBUG: Found project URL: %s\n", project)
			}
			if release, ok := sourceMap["release"].(string); ok && release != "" {
				sidecarConfig.ReleaseURL = release
				fmt.Printf("ADAPTER_SERVICE_DEBUG: Found release URL: %s\n", release)
			}
		}
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: Created sidecar config: %+v\n", sidecarConfig)
	return sidecarConfig
}

// sidecarMeta represents sidecar configuration from server metadata
type sidecarMeta struct {
	CommandType      string
	BaseImage        string
	Command          string
	Args             []string
	DockerImage      string
	DockerCommand    string
	DockerEntrypoint string
	Port             int
	Env              []map[string]string
}

// getSidecarMeta extracts sidecar configuration from server metadata
func (as *AdapterService) getSidecarMeta(server *models.MCPServer, envVars map[string]string) *sidecarMeta {
	fmt.Printf("DEBUG: getSidecarMeta called for server %s, Meta: %+v\n", server.Name, server.Meta)
	if server.Meta == nil {
		fmt.Printf("DEBUG: server.Meta is nil\n")
		return nil
	}

	sidecarConfig, ok := server.Meta["sidecarConfig"]
	if !ok {
		return nil
	}

	configMap, ok := sidecarConfig.(map[string]interface{})
	if !ok {
		return nil
	}

	meta := &sidecarMeta{}

	// Extract command type
	if commandType, ok := configMap["commandType"].(string); ok {
		meta.CommandType = commandType
	}

	// Extract command and args
	if command, ok := configMap["command"].(string); ok {
		meta.Command = command
	}
	if argsInterface, ok := configMap["args"].([]interface{}); ok {
		for _, arg := range argsInterface {
			if argStr, ok := arg.(string); ok {
				// Perform template substitution for placeholders like {{uyuni.server}}
				substitutedArg := as.substituteTemplates(argStr, envVars)
				meta.Args = append(meta.Args, substitutedArg)
			}
		}
	}

	if port, ok := configMap["port"].(float64); ok {
		meta.Port = int(port)
	}

	// Extract environment variables from env section
	if envInterface, ok := configMap["env"].([]interface{}); ok {
		for _, envItem := range envInterface {
			if envMap, ok := envItem.(map[string]interface{}); ok {
				envVar := make(map[string]string)
				if name, ok := envMap["name"].(string); ok {
					envVar["name"] = name
				}
				if value, ok := envMap["value"].(string); ok {
					envVar["value"] = value
				}
				if len(envVar) == 2 {
					meta.Env = append(meta.Env, envVar)
				}
			}
		}
	}

	// Parse -e flags from args (for docker run style commands)
	if len(meta.Args) > 0 {
		fmt.Printf("DEBUG: Parsing docker args: %+v\n", meta.Args)
		parsedArgs := []string{}
		i := 0
		for i < len(meta.Args) {
			arg := meta.Args[i]
			if arg == "-e" && i+1 < len(meta.Args) {
				// Parse -e KEY=VALUE
				envPair := meta.Args[i+1]
				if eqIndex := strings.Index(envPair, "="); eqIndex > 0 {
					key := envPair[:eqIndex]
					value := envPair[eqIndex+1:]
					fmt.Printf("DEBUG: Parsed env var: %s=%s\n", key, value)
					envVar := map[string]string{
						"name":  key,
						"value": value,
					}
					meta.Env = append(meta.Env, envVar)
				}
				i += 2 // Skip -e and the env var
			} else {
				// Keep all other args
				parsedArgs = append(parsedArgs, arg)
				i++
			}
		}
		meta.Args = parsedArgs
		fmt.Printf("DEBUG: Final args: %+v, env: %+v\n", meta.Args, meta.Env)
	}
	if port, ok := configMap["port"].(float64); ok {
		meta.Port = int(port)
	}

	// Return nil if required fields are missing
	if meta.CommandType == "" || meta.Command == "" {
		return nil
	}

	return meta
}
