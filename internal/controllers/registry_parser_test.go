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
	"strings"
	"testing"
)

func TestParseRegistryYAML_HappyPath(t *testing.T) {
	in := []byte(`
- name: uyuni
  description: SUSE Uyuni MCP server
  image: ghcr.io/uyuni-project/mcp-server-uyuni:latest
  meta:
    category: system-management
    tags:
      - uyuni
      - linux
  about:
    title: SUSE Uyuni
- name: github
  description: GitHub MCP server
  image: ghcr.io/github/github-mcp-server:latest
- name: filesystem
  url: https://example.com/fs
`)
	specs, names, warnings, err := ParseRegistryYAML(in)
	if err != nil {
		t.Fatalf("ParseRegistryYAML returned err: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if got, want := len(specs), 3; got != want {
		t.Fatalf("len(specs) = %d, want %d", got, want)
	}
	if got, want := len(names), 3; got != want {
		t.Fatalf("len(names) = %d, want %d", got, want)
	}
	if names[0] != "uyuni" || names[1] != "github" || names[2] != "filesystem" {
		t.Errorf("names = %v, want [uyuni github filesystem]", names)
	}

	uyuni := specs[0]
	if uyuni.DisplayName != "SUSE Uyuni" {
		t.Errorf("uyuni.DisplayName = %q, want %q", uyuni.DisplayName, "SUSE Uyuni")
	}
	if uyuni.Image != "ghcr.io/uyuni-project/mcp-server-uyuni:latest" {
		t.Errorf("uyuni.Image = %q", uyuni.Image)
	}
	if len(uyuni.Packages) != 1 || uyuni.Packages[0].Transport.Type != "stdio" {
		t.Errorf("uyuni.Packages = %+v, want one stdio package", uyuni.Packages)
	}
	if len(uyuni.Categories) != 1 || uyuni.Categories[0] != "system-management" {
		t.Errorf("uyuni.Categories = %v", uyuni.Categories)
	}
	if len(uyuni.Tags) != 2 {
		t.Errorf("uyuni.Tags = %v, want 2", uyuni.Tags)
	}

	if specs[2].URL != "https://example.com/fs" {
		t.Errorf("filesystem.URL = %q", specs[2].URL)
	}
	// URL-only entry has no image → no synthesized package.
	if len(specs[2].Packages) != 0 {
		t.Errorf("filesystem.Packages = %+v, want none (no image)", specs[2].Packages)
	}
}

func TestParseRegistryYAML_MissingNameSkipped(t *testing.T) {
	in := []byte(`
- name: ok
  image: img:1
- description: no-name entry
  image: img:2
- name: also-ok
  image: img:3
`)
	specs, names, warnings, err := ParseRegistryYAML(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(specs) != 2 || len(names) != 2 {
		t.Fatalf("specs=%d names=%d, want 2/2", len(specs), len(names))
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want 1", warnings)
	}
	if !strings.Contains(warnings[0], "entry[1]") {
		t.Errorf("warning should reference entry[1], got %q", warnings[0])
	}
}

func TestParseRegistryYAML_EmptyInput(t *testing.T) {
	specs, names, warnings, err := ParseRegistryYAML([]byte{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(specs) != 0 || len(names) != 0 || len(warnings) != 0 {
		t.Errorf("empty input should produce no output, got specs=%v names=%v warnings=%v",
			specs, names, warnings)
	}
}

func TestParseRegistryYAML_MalformedYAML(t *testing.T) {
	_, _, _, err := ParseRegistryYAML([]byte("not: [valid yaml"))
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"simple":           "simple",
		"UPPER":            "upper",
		"with space":       "with-space",
		"weird/slashes":    "weird-slashes",
		"dots.are.bad":     "dots-are-bad",
		"-leading-dashes-": "leading-dashes",
		"":                 "",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}

	long := strings.Repeat("a", 300)
	got := sanitizeName(long)
	if len(got) > 253 {
		t.Errorf("sanitizeName length cap broken: len=%d", len(got))
	}

	// Trailing-dash trim must happen *after* the length cap, in case the
	// 253rd character ends up being a `-` from the substitution.
	withTrailingDashAfterCap := strings.Repeat("a", 252) + "/x"
	got = sanitizeName(withTrailingDashAfterCap)
	if strings.HasSuffix(got, "-") {
		t.Errorf("sanitizeName must not leave trailing dash, got %q", got)
	}
}
