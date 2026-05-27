package services

import (
	"fmt"
	"regexp"
	"strings"

	"suse-ai-up/pkg/models"
)

// getMapKeys returns the keys of a map[string]interface{}
func getMapKeys(m map[string]interface{}) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// processCommandTemplates processes template variables in the sidecar command
func (as *AdapterService) processCommandTemplates(sidecarConfig *models.SidecarConfig, server *models.MCPServer) *models.SidecarConfig {
	fmt.Printf("ADAPTER_SERVICE_DEBUG: processCommandTemplates called with command: %s\n", sidecarConfig.Command)

	if sidecarConfig == nil || sidecarConfig.Command == "" {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: Returning early - sidecarConfig nil or empty command\n")
		return sidecarConfig
	}

	// Check if the command contains template variables
	if !strings.Contains(sidecarConfig.Command, "{{") {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: No template variables found in command\n")
		return sidecarConfig
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: Processing templates in command: %s\n", sidecarConfig.Command)
	fmt.Printf("ADAPTER_SERVICE_DEBUG: Server meta keys: %+v\n", getMapKeys(server.Meta))
	fmt.Printf("ADAPTER_SERVICE_DEBUG: Server meta: %+v\n", server.Meta)

	// Create a copy of the config to modify
	processedConfig := *sidecarConfig

	// Process template variables based on command type
	fmt.Printf("ADAPTER_SERVICE_DEBUG: CommandType: %s\n", sidecarConfig.CommandType)
	switch sidecarConfig.CommandType {
	case "docker":
		fmt.Printf("ADAPTER_SERVICE_DEBUG: Processing docker templates\n")
		processedConfig.Command = as.processDockerTemplates(sidecarConfig.Command, server)
	case "python", "npx", "go":
		fmt.Printf("ADAPTER_SERVICE_DEBUG: Processing python/npx/go templates\n")
		// For python/npx/go, templates are processed but the command structure may remain similar
		processedConfig.Command = as.processGenericTemplates(sidecarConfig.Command, server)
	default:
		// For unknown types, leave as-is
		fmt.Printf("ADAPTER_SERVICE_DEBUG: Unknown command type %s, skipping template processing\n", sidecarConfig.CommandType)
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: Processed command: %s\n", processedConfig.Command)
	return &processedConfig
}

// processDockerTemplates processes templates for docker commands
func (as *AdapterService) processDockerTemplates(command string, server *models.MCPServer) string {
	return as.processTemplates(command, server, func(varName, envName string) string {
		return fmt.Sprintf("-e %s=$%s", envName, envName)
	})
}

// processGenericTemplates processes templates for python/npx commands
func (as *AdapterService) processGenericTemplates(command string, server *models.MCPServer) string {
	fmt.Printf("ADAPTER_SERVICE_DEBUG: processGenericTemplates called with command: %s\n", command)
	// For generic commands, substitute template variables with environment variable references
	return as.processTemplatesGeneric(command, server)
}

// processTemplatesGeneric processes templates for generic commands, substituting all found templates
func (as *AdapterService) processTemplatesGeneric(command string, server *models.MCPServer) string {
	// Find all template variables in the command
	templateRegex := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	matches := templateRegex.FindAllStringSubmatch(command, -1)

	result := command
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		varName := strings.TrimSpace(match[1])

		// Look up the variable in config.secrets
		envName := as.lookupTemplatedVariableGeneric(varName, server)
		if envName == "" {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: Variable %s not found, skipping\n", varName)
			continue
		}

		// For generic commands, substitute with environment variable reference
		substitution := fmt.Sprintf("$%s", envName)
		templatePattern := fmt.Sprintf("{{%s}}", varName)
		result = strings.ReplaceAll(result, templatePattern, substitution)

		fmt.Printf("ADAPTER_SERVICE_DEBUG: Replaced %s with %s\n", templatePattern, substitution)
	}

	return result
}

// lookupTemplatedVariableGeneric looks up template variables for generic processing (always substitutes)
func (as *AdapterService) lookupTemplatedVariableGeneric(varName string, server *models.MCPServer) string {
	fmt.Printf("ADAPTER_SERVICE_DEBUG: lookupTemplatedVariableGeneric called for varName: %s\n", varName)

	if server.Meta == nil {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: server.Meta is nil\n")
		return ""
	}

	// First try direct secrets (new format)
	secretsRaw, ok := server.Meta["secrets"]
	if !ok {
		// Fall back to config.secrets (old format)
		fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets not found directly, trying config.secrets\n")
		configRaw, ok := server.Meta["config"]
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: config not found in server.Meta, available keys: %+v\n", getMapKeys(server.Meta))
			return ""
		}

		configMap, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: config is not a map, type: %T\n", configRaw)
			return ""
		}

		secretsRaw, ok = configMap["secrets"]
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets not found in config, available config keys: %+v\n", getMapKeys(configMap))
			return ""
		}
	}

	secretsSlice, ok := secretsRaw.([]interface{})
	if !ok {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets is not a slice, type: %T, value: %+v\n", secretsRaw, secretsRaw)
		return ""
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: Found %d secrets\n", len(secretsSlice))

	for _, secretRaw := range secretsSlice {
		secretMap, ok := secretRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this secret matches the variable name
		name, ok := secretMap["name"].(string)
		if !ok || name != varName {
			continue
		}

		// Get the environment variable name
		envName, ok := secretMap["env"].(string)
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: Variable %s missing env field\n", varName)
			return ""
		}

		fmt.Printf("ADAPTER_SERVICE_DEBUG: Found variable %s -> %s\n", varName, envName)
		return envName
	}

	return ""
}

// processTemplates processes template variables using a custom substitution function
func (as *AdapterService) processTemplates(command string, server *models.MCPServer, substituteFunc func(varName, envName string) string) string {
	// Find all template variables in the command
	templateRegex := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	matches := templateRegex.FindAllStringSubmatch(command, -1)

	result := command
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		varName := strings.TrimSpace(match[1])
		fmt.Printf("ADAPTER_SERVICE_DEBUG: Found template variable: %s\n", varName)

		// Look up the variable in config.secrets
		envName := as.lookupTemplatedVariable(varName, server)
		if envName == "" {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: Variable %s not found or not templated, skipping\n", varName)
			continue
		}

		// Apply the substitution function
		substitution := substituteFunc(varName, envName)
		templatePattern := fmt.Sprintf("{{%s}}", varName)
		result = strings.ReplaceAll(result, templatePattern, substitution)

		fmt.Printf("ADAPTER_SERVICE_DEBUG: Replaced %s with %s\n", templatePattern, substitution)
	}

	return result
}

// lookupTemplatedVariable looks up a variable name in the server's secrets
func (as *AdapterService) lookupTemplatedVariable(varName string, server *models.MCPServer) string {
	fmt.Printf("ADAPTER_SERVICE_DEBUG: lookupTemplatedVariable called for varName: %s\n", varName)

	if server.Meta == nil {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: server.Meta is nil\n")
		return ""
	}

	// First try direct secrets (new format)
	secretsRaw, ok := server.Meta["secrets"]
	if !ok {
		// Fall back to config.secrets (old format)
		fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets not found directly, trying config.secrets\n")
		configRaw, ok := server.Meta["config"]
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: config not found in server.Meta, available keys: %+v\n", getMapKeys(server.Meta))
			return ""
		}

		configMap, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: config is not a map, type: %T\n", configRaw)
			return ""
		}

		secretsRaw, ok = configMap["secrets"]
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets not found in config, available config keys: %+v\n", getMapKeys(configMap))
			return ""
		}
	}

	secretsSlice, ok := secretsRaw.([]interface{})
	if !ok {
		fmt.Printf("ADAPTER_SERVICE_DEBUG: secrets is not a slice, type: %T, value: %+v\n", secretsRaw, secretsRaw)
		return ""
	}

	fmt.Printf("ADAPTER_SERVICE_DEBUG: Found %d secrets\n", len(secretsSlice))

	for _, secretRaw := range secretsSlice {
		secretMap, ok := secretRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this secret matches the variable name
		name, ok := secretMap["name"].(string)
		if !ok || name != varName {
			continue
		}

		// Note: We now process all variables, not just templated ones

		// Get the environment variable name
		envName, ok := secretMap["env"].(string)
		if !ok {
			fmt.Printf("ADAPTER_SERVICE_DEBUG: Variable %s missing env field\n", varName)
			return ""
		}

		fmt.Printf("ADAPTER_SERVICE_DEBUG: Found templated variable %s -> %s\n", varName, envName)
		return envName
	}

	return ""
}

// substituteTemplates replaces template placeholders like {{uyuni.server}} with actual values
func (as *AdapterService) substituteTemplates(template string, envVars map[string]string) string {
	result := template

	// Replace {{variable}} patterns with values from envVars
	for key, value := range envVars {
		// Convert env var names to template format (e.g., UYUNI_SERVER -> uyuni.server)
		templateKey := strings.ToLower(strings.ReplaceAll(key, "_", "."))
		placeholder := "{{" + templateKey + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}
