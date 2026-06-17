/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"encoding/json"
	"fmt"
	"strings"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// ---------- internal JSON-unmarshal types ----------

type registryJSON struct {
	Servers  []registryEntry  `json:"servers"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

type registryEntry struct {
	Server registryServer         `json:"server"`
	Meta   map[string]metaStatus  `json:"_meta,omitempty"`
}

type registryServer struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Title       string              `json:"title"`
	Version     string              `json:"version"`
	Repository  *registryRepo       `json:"repository,omitempty"`
	Packages    []registryPackage   `json:"packages,omitempty"`
	Remotes     []registryRemote    `json:"remotes,omitempty"`
}

type registryRepo struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

type registryPackage struct {
	RegistryType         string              `json:"registryType"`
	Identifier           string              `json:"identifier"`
	Transport            registryTransport   `json:"transport"`
	EnvironmentVariables []registryEnvVar    `json:"environmentVariables,omitempty"`
}

type registryTransport struct {
	Type string `json:"type"`
}

type registryEnvVar struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSecret    bool   `json:"isSecret"`
}

type registryRemote struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type metaStatus struct {
	Status   string `json:"status"`
	IsLatest *bool  `json:"isLatest,omitempty"`
}

// ---------- public parser ----------

// ParseMCPRegistryJSON parses the official MCP registry JSON format
// (registry.modelcontextprotocol.io/v0.1/servers) into MCPServerSpec values.
//
// Entries missing a server.name are skipped and recorded as warnings.
// Entries whose _meta marks them as non-active or not-latest are also
// skipped (silently). When _meta is absent or does not contain the
// official key the entry is included.
//
// err is reserved for unmarshal failures — per-entry problems surface as
// warnings only.
func ParseMCPRegistryJSON(data []byte) (specs []mcpv1alpha1.MCPServerSpec, names []string, warnings []string, err error) {
	if len(data) == 0 {
		return nil, nil, nil, nil
	}

	var reg registryJSON
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, nil, nil, fmt.Errorf("parse MCP registry JSON: %w", err)
	}

	for i, entry := range reg.Servers {
		// Skip entries that the registry marks inactive or superseded.
		if !isActiveLatest(entry.Meta) {
			continue
		}

		srv := entry.Server
		if srv.Name == "" {
			warnings = append(warnings, fmt.Sprintf("servers[%d] skipped: missing required field 'server.name'", i))
			continue
		}

		spec := mcpv1alpha1.MCPServerSpec{
			DisplayName: srv.Title,
			Description: srv.Description,
			Version:     srv.Version,
		}

		// Repository
		if srv.Repository != nil && srv.Repository.URL != "" {
			spec.Repository = &mcpv1alpha1.MCPServerRepository{
				URL:    srv.Repository.URL,
				Source: srv.Repository.Source,
			}
		}

		// Packages
		for _, pkg := range srv.Packages {
			p := mcpv1alpha1.MCPServerPackage{
				RegistryType: pkg.RegistryType,
				Identifier:   pkg.Identifier,
				Transport:    mcpv1alpha1.MCPServerTransport{Type: pkg.Transport.Type},
			}
			for _, ev := range pkg.EnvironmentVariables {
				p.EnvironmentVariables = append(p.EnvironmentVariables, mcpv1alpha1.MCPServerEnvVar{
					Name:        ev.Name,
					Description: ev.Description,
					IsSecret:    ev.IsSecret,
				})
			}
			spec.Packages = append(spec.Packages, p)

			// OCI / Docker package → spec.Image
			if spec.Image == "" && (pkg.RegistryType == "oci" || pkg.RegistryType == "docker") {
				spec.Image = pkg.Identifier
			}
		}

		// Remotes → spec.URL (first streamable-http or sse wins)
		if spec.URL == "" {
			for _, r := range srv.Remotes {
				if r.Type == "streamable-http" || r.Type == "sse" {
					spec.URL = r.URL
					break
				}
			}
		}

		specs = append(specs, spec)

		// Derive a short name from the last segment of the qualified name.
		shortName := srv.Name
		if idx := strings.LastIndex(shortName, "/"); idx >= 0 && idx < len(shortName)-1 {
			shortName = shortName[idx+1:]
		}
		names = append(names, shortName)
	}

	return specs, names, warnings, nil
}

// isActiveLatest checks the _meta block. If the official key
// ("io.modelcontextprotocol.registry/official") is present, the entry
// must have status "active" and isLatest must not be explicitly false.
// When _meta is nil or the key is absent the entry is accepted.
func isActiveLatest(meta map[string]metaStatus) bool {
	if meta == nil {
		return true
	}
	official, ok := meta["io.modelcontextprotocol.registry/official"]
	if !ok {
		return true
	}
	if official.Status != "" && official.Status != "active" {
		return false
	}
	if official.IsLatest != nil && !*official.IsLatest {
		return false
	}
	return true
}
