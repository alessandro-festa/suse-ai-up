package services

import (
	"fmt"
	"strings"
)

// ParseTrentoConfig parses the TRENTO_CONFIG environment-variable format
// "TRENTO_URL={url},TOKEN={pat}" used by the suse-trento MCP server. It
// returns the URL and the personal access token separately so callers can
// rewrite the adapter's environment variables and authentication config.
func ParseTrentoConfig(config string) (trentoURL, token string, err error) {
	if config == "" {
		return "", "", fmt.Errorf("TRENTO_CONFIG cannot be empty")
	}

	parts := strings.Split(config, ",")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid TRENTO_CONFIG format, expected 'TRENTO_URL={url},TOKEN={pat}'")
	}

	var urlPart, tokenPart string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "TRENTO_URL=") {
			urlPart = strings.TrimPrefix(part, "TRENTO_URL=")
		} else if strings.HasPrefix(part, "TOKEN=") {
			tokenPart = strings.TrimPrefix(part, "TOKEN=")
		}
	}

	if urlPart == "" {
		return "", "", fmt.Errorf("TRENTO_URL not found in TRENTO_CONFIG")
	}
	if tokenPart == "" {
		return "", "", fmt.Errorf("TOKEN not found in TRENTO_CONFIG")
	}

	return urlPart, tokenPart, nil
}
