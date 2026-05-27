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
	"sort"
	"strings"
	"testing"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func TestApplySelector_NilReturnsEmpty(t *testing.T) {
	got, diag := applySelector([]string{"a", "b"}, nil)
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
	if diag != "" {
		t.Errorf("diag = %q, want empty", diag)
	}
}

func TestApplySelector_All(t *testing.T) {
	got, _ := applySelector([]string{"a", "b", "c"}, &mcpv1alpha1.VirtualMCPSelector{All: true})
	if want := []string{"a", "b", "c"}; !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplySelector_Names(t *testing.T) {
	got, _ := applySelector(
		[]string{"a", "b", "c"},
		&mcpv1alpha1.VirtualMCPSelector{Names: []string{"b", "d"}},
	)
	if want := []string{"b"}; !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplySelector_Prefix(t *testing.T) {
	got, _ := applySelector(
		[]string{"foo", "foobar", "qux"},
		&mcpv1alpha1.VirtualMCPSelector{Prefix: "foo"},
	)
	if want := []string{"foo", "foobar"}; !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplySelector_Regex(t *testing.T) {
	got, _ := applySelector(
		[]string{"alpha", "beta", "alfa"},
		&mcpv1alpha1.VirtualMCPSelector{Regex: "^al"},
	)
	if want := []string{"alpha", "alfa"}; !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplySelector_RegexInvalid(t *testing.T) {
	got, diag := applySelector(
		[]string{"a"},
		&mcpv1alpha1.VirtualMCPSelector{Regex: "(unterminated"},
	)
	if len(got) != 0 {
		t.Errorf("got %v, want empty on invalid regex", got)
	}
	if !strings.Contains(diag, "invalid regex") {
		t.Errorf("diag = %q, want it to mention 'invalid regex'", diag)
	}
}

func TestApplySelector_PrecedenceNamesOverPrefix(t *testing.T) {
	// Names + Prefix → Names wins, diagnostic mentions precedence.
	got, diag := applySelector(
		[]string{"foo", "bar", "foobar"},
		&mcpv1alpha1.VirtualMCPSelector{Names: []string{"bar"}, Prefix: "foo"},
	)
	if want := []string{"bar"}; !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !strings.Contains(diag, "precedence") {
		t.Errorf("diag = %q, want it to mention precedence", diag)
	}
}

func TestApplyRewrite_Identity(t *testing.T) {
	got := applyRewrite([]string{"a", "b"}, nil)
	if len(got) != 2 || got[0].Exposed != "a" || got[0].Original != "" || got[1].Exposed != "b" {
		t.Errorf("nil rewrite did not produce identity: %+v", got)
	}
}

func TestApplyRewrite_EmptyRewriteIsIdentity(t *testing.T) {
	got := applyRewrite([]string{"a"}, &mcpv1alpha1.VirtualMCPSourceRewrite{})
	if len(got) != 1 || got[0].Exposed != "a" || got[0].Original != "" {
		t.Errorf("empty rewrite did not produce identity: %+v", got)
	}
}

func TestApplyRewrite_PrefixOnly(t *testing.T) {
	got := applyRewrite([]string{"x"}, &mcpv1alpha1.VirtualMCPSourceRewrite{Prefix: "pre_"})
	if got[0].Exposed != "pre_x" || got[0].Original != "x" {
		t.Errorf("got %+v, want Exposed=pre_x Original=x", got[0])
	}
}

func TestApplyRewrite_SuffixOnly(t *testing.T) {
	got := applyRewrite([]string{"x"}, &mcpv1alpha1.VirtualMCPSourceRewrite{Suffix: "_suf"})
	if got[0].Exposed != "x_suf" || got[0].Original != "x" {
		t.Errorf("got %+v, want Exposed=x_suf Original=x", got[0])
	}
}

func TestApplyRewrite_PrefixAndSuffix(t *testing.T) {
	got := applyRewrite([]string{"x"}, &mcpv1alpha1.VirtualMCPSourceRewrite{Prefix: "pre_", Suffix: "_suf"})
	if got[0].Exposed != "pre_x_suf" || got[0].Original != "x" {
		t.Errorf("got %+v, want Exposed=pre_x_suf Original=x", got[0])
	}
}

func TestApplyRewrite_Empty(t *testing.T) {
	got := applyRewrite(nil, &mcpv1alpha1.VirtualMCPSourceRewrite{Prefix: "p_"})
	if len(got) != 0 {
		t.Errorf("got %v, want empty for empty input", got)
	}
}

func TestFlattenSources_DistinctNamesPassThrough(t *testing.T) {
	srcs := []resolvedSource{
		{
			SourceAdapter: "ada",
			Tools:         []resolvedEntry{{Exposed: "ada_search", Original: "search"}},
		},
		{
			SourceMCPServer: "srv",
			Tools:           []resolvedEntry{{Exposed: "srv_search", Original: "search"}},
			Resources:       []resolvedEntry{{Exposed: "doc"}},
		},
	}
	entries, collisions := flattenSources(srcs)
	if len(collisions) != 0 {
		t.Errorf("collisions = %v, want none", collisions)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}

	byName := map[string]mcpv1alpha1.ResolvedEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}

	if e := byName["ada_search"]; e.Kind != mcpv1alpha1.ResolvedEntryKindTool || e.SourceAdapter != "ada" {
		t.Errorf("ada_search = %+v, want Kind=tool SourceAdapter=ada", e)
	}
	if e := byName["srv_search"]; e.Kind != mcpv1alpha1.ResolvedEntryKindTool || e.SourceMCPServer != "srv" {
		t.Errorf("srv_search = %+v, want Kind=tool SourceMCPServer=srv", e)
	}
	if e := byName["doc"]; e.Kind != mcpv1alpha1.ResolvedEntryKindResource {
		t.Errorf("doc.Kind = %q, want resource", e.Kind)
	}
}

func TestFlattenSources_CollisionDropsBoth(t *testing.T) {
	srcs := []resolvedSource{
		{
			SourceAdapter: "ada",
			Tools:         []resolvedEntry{{Exposed: "search"}},
		},
		{
			SourceMCPServer: "srv",
			Tools:           []resolvedEntry{{Exposed: "search"}},
		},
	}
	entries, collisions := flattenSources(srcs)
	if len(entries) != 0 {
		t.Errorf("entries = %+v, want both dropped on collision", entries)
	}
	if len(collisions) != 1 || collisions[0] != "tool/search" {
		t.Errorf("collisions = %v, want [tool/search]", collisions)
	}
}

func TestFlattenSources_KindIsolatedNoFalseCollision(t *testing.T) {
	// Same name across different kinds (tool/search vs resource/search)
	// must NOT collide — they live in different MCP catalogs.
	srcs := []resolvedSource{
		{
			SourceAdapter: "ada",
			Tools:         []resolvedEntry{{Exposed: "search"}},
			Resources:     []resolvedEntry{{Exposed: "search"}},
		},
	}
	entries, collisions := flattenSources(srcs)
	if len(collisions) != 0 {
		t.Errorf("collisions = %v, want none across kinds", collisions)
	}
	if len(entries) != 2 {
		t.Errorf("len(entries) = %d, want 2 (one per kind)", len(entries))
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac, bc := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
