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
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/services/virtualmcp"
)

// ProbeResult is the outcome of a single plugin health probe. ResponseTime
// is the measured round trip from the probe start, including the timeout
// wait when the probe failed.
type ProbeResult struct {
	Healthy      bool
	Message      string
	ResponseTime time.Duration
}

// PluginProber is the dependency PluginReconciler holds for liveness and
// capability discovery. The concrete *Prober satisfies it; tests can plug
// in a fake without spinning up an httptest.Server.
type PluginProber interface {
	Probe(ctx context.Context, serviceType mcpv1alpha1.PluginServiceType, serviceURL, path string, timeout time.Duration) ProbeResult
	DiscoverCapabilities(ctx context.Context, serviceID, serviceURL string) ([]mcpv1alpha1.PluginCapability, error)
}

// Prober implements PluginProber. It reuses virtualmcp.Discoverer for
// virtualmcp-typed plugins so health and discovery semantics stay in
// lockstep with the pre-CRD path in pkg/plugins/manager.go.
type Prober struct {
	httpClient *http.Client
	discoverer *virtualmcp.Discoverer
}

// NewProber builds a Prober. A nil httpClient defaults to a 30s-timeout
// client to match the previous in-process plugin manager behavior.
func NewProber(httpClient *http.Client) *Prober {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Prober{
		httpClient: httpClient,
		discoverer: virtualmcp.NewDiscoverer(httpClient),
	}
}

// Probe performs one liveness check. For virtualmcp plugins it delegates
// to virtualmcp.Discoverer.CheckHealth (which probes both /health and
// /api/v1/mcps); other types do a single GET on serviceURL+path and treat
// any 2xx as healthy.
func (p *Prober) Probe(ctx context.Context, serviceType mcpv1alpha1.PluginServiceType, serviceURL, path string, timeout time.Duration) ProbeResult {
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if serviceType == mcpv1alpha1.PluginServiceTypeVirtualMCP {
		status := p.discoverer.CheckHealth(probeCtx, serviceURL)
		return ProbeResult{
			Healthy:      status.Status == "healthy",
			Message:      status.Message,
			ResponseTime: time.Since(start),
		}
	}

	target := strings.TrimRight(serviceURL, "/") + path
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{
			Healthy:      false,
			Message:      fmt.Sprintf("build probe request: %v", err),
			ResponseTime: time.Since(start),
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return ProbeResult{
			Healthy:      false,
			Message:      fmt.Sprintf("probe failed: %v", err),
			ResponseTime: time.Since(start),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProbeResult{
			Healthy:      false,
			Message:      fmt.Sprintf("probe returned status %d", resp.StatusCode),
			ResponseTime: time.Since(start),
		}
	}

	return ProbeResult{
		Healthy:      true,
		Message:      fmt.Sprintf("probe returned status %d", resp.StatusCode),
		ResponseTime: time.Since(start),
	}
}

// DiscoverCapabilities calls the virtualmcp discovery endpoint and
// projects each discovered MCP server into a PluginCapability. The
// projection uses /api/v1/mcps/<id> as the Path so the existing
// ServiceManager.pathMatchesCapability prefix matcher
// (pkg/plugins/manager.go:290) keeps routing requests correctly after
// the reconciler reflects the result back into the in-process store.
func (p *Prober) DiscoverCapabilities(ctx context.Context, serviceID, serviceURL string) ([]mcpv1alpha1.PluginCapability, error) {
	servers, err := p.discoverer.Discover(ctx, serviceID, serviceURL)
	if err != nil {
		return nil, err
	}
	caps := make([]mcpv1alpha1.PluginCapability, 0, len(servers))
	for _, srv := range servers {
		if srv == nil || srv.ID == "" {
			continue
		}
		caps = append(caps, mcpv1alpha1.PluginCapability{
			Path:        "/api/v1/mcps/" + srv.ID,
			Methods:     []string{http.MethodGet},
			Description: srv.Description,
		})
	}
	return caps, nil
}
