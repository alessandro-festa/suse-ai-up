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
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// rfc1123InvalidRunes matches characters that are not valid in an RFC 1123
// label after lowering. Used by sanitizeName to derive child CR names that
// Kubernetes will accept as object metadata.Name values.
var rfc1123InvalidRunes = regexp.MustCompile(`[^a-z0-9-]+`)

// ParseRegistryYAML parses a registry YAML payload (matching the legacy
// hack/registry/mcp_registry.yaml format) into MCPServerSpec values suitable
// for use as child MCPServer.Spec or as MCPRegistry.Spec.Source.Inline
// entries.
//
// Entries missing the required `name` field are skipped and the index is
// recorded in warnings; this mirrors loader.ParseAndUploadRegistryYAML so
// existing registry YAMLs keep working after the migration to CRs.
//
// err is reserved for unmarshal/parse failures — never for per-entry
// problems, which surface as warnings instead.
func ParseRegistryYAML(data []byte) (specs []mcpv1alpha1.MCPServerSpec, names []string, warnings []string, err error) {
	if len(data) == 0 {
		return nil, nil, nil, nil
	}
	var raw []map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, nil, fmt.Errorf("parse registry YAML: %w", err)
	}

	for i, entry := range raw {
		name, _ := entry["name"].(string)
		if name == "" {
			warnings = append(warnings, fmt.Sprintf("entry[%d] skipped: missing required field 'name'", i))
			continue
		}
		spec := mapToMCPServerSpec(entry)
		specs = append(specs, spec)
		names = append(names, name)
	}
	return specs, names, warnings, nil
}

// mapToMCPServerSpec projects the loose YAML map shape into the typed
// MCPServerSpec. Unknown keys are dropped — the legacy `_meta` stash that
// loader.go carries through belongs on models.MCPServer, not on the CR.
func mapToMCPServerSpec(entry map[string]interface{}) mcpv1alpha1.MCPServerSpec {
	spec := mcpv1alpha1.MCPServerSpec{}

	if v, ok := entry["description"].(string); ok {
		spec.Description = v
	}
	if v, ok := entry["version"].(string); ok {
		spec.Version = v
	}
	if v, ok := entry["image"].(string); ok && v != "" && v != "none" {
		spec.Image = v
		spec.Packages = []mcpv1alpha1.MCPServerPackage{{
			RegistryType: "oci",
			Identifier:   v,
			Transport:    mcpv1alpha1.MCPServerTransport{Type: "stdio"},
		}}
	}
	if v, ok := entry["url"].(string); ok {
		spec.URL = v
	}
	if about, ok := entry["about"].(map[string]interface{}); ok {
		if title, ok := about["title"].(string); ok {
			spec.DisplayName = title
		}
		if spec.Description == "" {
			if desc, ok := about["description"].(string); ok {
				spec.Description = desc
			}
		}
	}
	if meta, ok := entry["meta"].(map[string]interface{}); ok {
		if cat, ok := meta["category"].(string); ok && cat != "" {
			spec.Categories = []string{cat}
		}
		if tags, ok := meta["tags"].([]interface{}); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					spec.Tags = append(spec.Tags, s)
				}
			}
		}
		if sc, ok := meta["sidecarConfig"].(map[string]interface{}); ok {
			if ct, ok := sc["commandType"].(string); ok {
				spec.CommandType = ct
			}
			if cmd, ok := sc["command"].(string); ok {
				spec.Command = cmd
			}
			if spec.Port == 0 {
				switch p := sc["port"].(type) {
				case int:
					spec.Port = int32(p)
				case float64:
					spec.Port = int32(p)
				}
			}
		}
	}
	if src, ok := entry["source"].(map[string]interface{}); ok {
		if url, ok := src["project"].(string); ok && url != "" {
			spec.Repository = &mcpv1alpha1.MCPServerRepository{URL: url, Source: "git"}
		}
	}
	return spec
}

// sanitizeName converts an arbitrary identifier into an RFC 1123 label
// suitable for use as a Kubernetes object name. The transform is
// lossy-but-deterministic: same input always yields the same output, so
// MCPRegistryReconciler can re-derive child names across reconciles
// without storing them.
func sanitizeName(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	s = rfc1123InvalidRunes.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 253 {
		s = s[:253]
		s = strings.TrimRight(s, "-")
	}
	return s
}
