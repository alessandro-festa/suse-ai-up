package loader

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

type fakeManager struct {
	uploaded  []*models.MCPServer
	cleared   int
	uploadErr error
	clearErr  error
}

func (f *fakeManager) UploadRegistryEntries(entries []*models.MCPServer) error {
	if f.uploadErr != nil {
		return f.uploadErr
	}
	f.uploaded = append(f.uploaded, entries...)
	return nil
}

func (f *fakeManager) Clear() error {
	f.cleared++
	return f.clearErr
}

const sampleYAML = `
- name: example-stdio
  description: an example
  image: ghcr.io/example/mcp:latest
  meta:
    keep: me
  about:
    homepage: https://example.com
  config:
    foo: bar
  type: localstdio
- name: skipme-no-name-field-below
- description: missing name, should be dropped
`

func TestParseAndUploadRegistryYAML_HappyPath(t *testing.T) {
	mgr := &fakeManager{}
	if err := ParseAndUploadRegistryYAML([]byte(sampleYAML), mgr, "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mgr.uploaded) != 2 {
		t.Fatalf("expected 2 servers uploaded (one entry skipped), got %d", len(mgr.uploaded))
	}
	got := mgr.uploaded[0]
	if got.Name != "example-stdio" || got.ID != "example-stdio" {
		t.Errorf("name/ID = %q/%q, want example-stdio", got.Name, got.ID)
	}
	if len(got.Packages) != 1 || got.Packages[0].Identifier != "ghcr.io/example/mcp:latest" {
		t.Errorf("package identifier = %+v, want image populated", got.Packages)
	}
	if got.Meta["source"] != "yaml" {
		t.Errorf("meta.source = %v, want yaml", got.Meta["source"])
	}
	if got.Meta["keep"] != "me" {
		t.Errorf("preserved meta lost: %+v", got.Meta)
	}
	if got.Meta["about"] == nil || got.Meta["config"] == nil || got.Meta["type"] != "localstdio" {
		t.Errorf("about/config/type not folded into meta: %+v", got.Meta)
	}
}

func TestParseAndUploadRegistryYAML_BadYAML(t *testing.T) {
	mgr := &fakeManager{}
	err := ParseAndUploadRegistryYAML([]byte("::not yaml::"), mgr, "test")
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestParseAndUploadRegistryYAML_UploadErrorWrapped(t *testing.T) {
	wantErr := errors.New("boom")
	mgr := &fakeManager{uploadErr: wantErr}
	err := ParseAndUploadRegistryYAML([]byte(sampleYAML), mgr, "test")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped upload error, got %v", err)
	}
}

func TestLoadInitialRegistry_FromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleYAML))
	}))
	defer srv.Close()

	mgr := &fakeManager{}
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "5s"}

	if err := LoadInitialRegistry(context.Background(), mgr, cfg); err != nil {
		t.Fatalf("LoadInitialRegistry returned error: %v", err)
	}
	if mgr.cleared != 1 {
		t.Errorf("expected Clear called once, got %d", mgr.cleared)
	}
	if len(mgr.uploaded) != 2 {
		t.Errorf("expected 2 uploaded, got %d", len(mgr.uploaded))
	}
}

func TestLoadInitialRegistry_FileFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DefaultRegistryFile), []byte(sampleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{}
	cfg := &config.Config{MCPRegistryURL: srv.URL, RegistryTimeout: "5s"}

	if err := LoadInitialRegistry(context.Background(), mgr, cfg); err != nil {
		t.Fatalf("LoadInitialRegistry returned error: %v", err)
	}
	if len(mgr.uploaded) != 2 {
		t.Errorf("expected 2 uploaded from file fallback, got %d", len(mgr.uploaded))
	}
}

func TestLoadInitialRegistry_NoConfigNoOp(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{}
	cfg := &config.Config{}

	if err := LoadInitialRegistry(context.Background(), mgr, cfg); err != nil {
		t.Fatalf("expected nil with no config, got %v", err)
	}
	if len(mgr.uploaded) != 0 {
		t.Errorf("expected nothing uploaded, got %d", len(mgr.uploaded))
	}
	if mgr.cleared != 1 {
		t.Errorf("Clear should be called even when no source configured (%d)", mgr.cleared)
	}
}
