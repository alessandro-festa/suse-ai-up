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

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/services/virtualmcp"
)

// resolvedEntry is the per-entry intermediate produced after a selector +
// rewrite pass. The reconciler builds these per (source, kind) pair, then
// flattenSources merges them into the final []ResolvedEntry that lands on
// VirtualMCPRoute.Status.
type resolvedEntry struct {
	Exposed  string
	Original string
}

// resolvedSource holds one source's selected-and-rewritten entries.
// Either SourceAdapter or SourceMCPServer is set (never both), reflecting
// which kind of reference the source carried in Spec.
type resolvedSource struct {
	SourceAdapter   string
	SourceMCPServer string
	Tools           []resolvedEntry
	Resources       []resolvedEntry
	Prompts         []resolvedEntry
}

// applySelector returns the subset of names matched by sel. A nil selector
// matches nothing — callers that want "all" must say so explicitly via
// {all: true}. Precedence when more than one field is set is
// Names > Prefix > Regex > All, with a diagnostic message describing the
// choice; the diagnostic is empty when the selector is unambiguous.
func applySelector(names []string, sel *mcpv1alpha1.VirtualMCPSelector) (matched []string, diag string) {
	if sel == nil {
		return nil, ""
	}

	setCount := 0
	if len(sel.Names) > 0 {
		setCount++
	}
	if sel.Prefix != "" {
		setCount++
	}
	if sel.Regex != "" {
		setCount++
	}
	if sel.All {
		setCount++
	}
	if setCount > 1 {
		diag = "selector has multiple fields set; precedence Names>Prefix>Regex>All applied"
	}

	switch {
	case len(sel.Names) > 0:
		want := make(map[string]bool, len(sel.Names))
		for _, n := range sel.Names {
			want[n] = true
		}
		for _, n := range names {
			if want[n] {
				matched = append(matched, n)
			}
		}
		return matched, diag

	case sel.Prefix != "":
		for _, n := range names {
			if strings.HasPrefix(n, sel.Prefix) {
				matched = append(matched, n)
			}
		}
		return matched, diag

	case sel.Regex != "":
		re, err := regexp.Compile(sel.Regex)
		if err != nil {
			return nil, fmt.Sprintf("invalid regex %q: %v", sel.Regex, err)
		}
		for _, n := range names {
			if re.MatchString(n) {
				matched = append(matched, n)
			}
		}
		return matched, diag

	case sel.All:
		out := make([]string, len(names))
		copy(out, names)
		return out, diag
	}

	return nil, ""
}

// applyRewrite maps post-selector names through the source's Rewrite
// (Prefix and/or Suffix). A nil rewrite means identity: Exposed=name,
// Original="" so downstream code knows no rewrite was applied.
func applyRewrite(names []string, rw *mcpv1alpha1.VirtualMCPSourceRewrite) []resolvedEntry {
	out := make([]resolvedEntry, 0, len(names))
	if rw == nil || (rw.Prefix == "" && rw.Suffix == "") {
		for _, n := range names {
			out = append(out, resolvedEntry{Exposed: n})
		}
		return out
	}
	for _, n := range names {
		out = append(out, resolvedEntry{
			Exposed:  rw.Prefix + n + rw.Suffix,
			Original: n,
		})
	}
	return out
}

// flattenSources merges per-source resolved entries into the final
// status-shaped catalog. Collisions (two sources producing the same
// Exposed name within the same Kind) drop both contributing entries and
// surface the collision name to the caller — the caller decides whether
// to mark the route Conflict or fail it.
func flattenSources(srcs []resolvedSource) (entries []mcpv1alpha1.ResolvedEntry, collisions []string) {
	type slot struct {
		entry mcpv1alpha1.ResolvedEntry
		count int
	}
	tools := map[string]*slot{}
	resources := map[string]*slot{}
	prompts := map[string]*slot{}

	addAll := func(bucket map[string]*slot, kind mcpv1alpha1.ResolvedEntryKind, src resolvedSource, entries []resolvedEntry) {
		for _, e := range entries {
			s, ok := bucket[e.Exposed]
			if !ok {
				bucket[e.Exposed] = &slot{
					entry: mcpv1alpha1.ResolvedEntry{
						Name:            e.Exposed,
						Kind:            kind,
						OriginalName:    e.Original,
						SourceAdapter:   src.SourceAdapter,
						SourceMCPServer: src.SourceMCPServer,
					},
					count: 1,
				}
				continue
			}
			s.count++
		}
	}

	for _, src := range srcs {
		addAll(tools, mcpv1alpha1.ResolvedEntryKindTool, src, src.Tools)
		addAll(resources, mcpv1alpha1.ResolvedEntryKindResource, src, src.Resources)
		addAll(prompts, mcpv1alpha1.ResolvedEntryKindPrompt, src, src.Prompts)
	}

	finalize := func(bucket map[string]*slot, kind string) {
		for name, s := range bucket {
			if s.count > 1 {
				collisions = append(collisions, fmt.Sprintf("%s/%s", kind, name))
				continue
			}
			entries = append(entries, s.entry)
		}
	}
	finalize(tools, "tool")
	finalize(resources, "resource")
	finalize(prompts, "prompt")

	return entries, collisions
}

// catalogNames extracts the .Name field from a slice of CatalogEntry —
// applySelector operates on plain strings so it doesn't need the rest of
// the entry shape (and so the tests can stay string-only).
func catalogNames(in []virtualmcp.CatalogEntry) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = in[i].Name
	}
	return out
}
