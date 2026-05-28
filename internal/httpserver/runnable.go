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

// Package httpserver wraps the SUSE AI Uniproxy HTTP server as a
// controller-runtime manager.Runnable so it can run inside the operator
// process alongside the reconcilers. The Runnable is the consolidation
// point P2.4 needs: the gin router gets its services from the same
// bootstrap path the legacy cmd/uniproxy used, but the caller (cmd/manager)
// passes through shared in-process stores via bootstrap.SharedStores so
// the HTTP handlers and reconcilers see the same state.
package httpserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/SUSE/suse-ai-up/internal/bootstrap"
	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/router"
)

const shutdownTimeout = 30 * time.Second

// Runnable is the manager.Runnable + LeaderElectionRunnable implementation
// that hosts the HTTP server. HTTP handlers serve traffic on every pod, so
// NeedLeaderElection returns false — gating the data plane on leader
// election would 503 every non-leader replica.
type Runnable struct {
	Cfg    *config.Config
	Shared bootstrap.SharedStores
}

// NewRunnable returns a Runnable configured to call bootstrap.BootstrapWithStores
// at Start time. Bootstrap is intentionally deferred to Start so the OTEL
// init (which dials the collector) doesn't run during cmd/manager wiring.
func NewRunnable(cfg *config.Config, shared bootstrap.SharedStores) *Runnable {
	return &Runnable{Cfg: cfg, Shared: shared}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable. HTTP handlers
// must serve on every replica; returning false ensures the manager starts the
// runnable regardless of leader state.
func (r *Runnable) NeedLeaderElection() bool { return false }

// Start wires the gin router, starts ListenAndServe in a goroutine, and
// blocks until ctx is canceled. On cancellation it triggers graceful
// shutdown with shutdownTimeout. Implements manager.Runnable.
func (r *Runnable) Start(ctx context.Context) error {
	if r.Cfg.AuthMode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	engine := gin.New()
	engine.Use(gin.CustomRecovery(func(c *gin.Context, recovered any) {
		log.Printf("Panic recovered: %v", recovered)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "An unexpected error occurred",
		})
	}))

	if r.Cfg.OtelEnabled {
		engine.Use(otelgin.Middleware("suse-ai-up"))
	}

	svc, err := bootstrap.BootstrapWithStores(ctx, r.Cfg, r.Shared)
	if err != nil {
		return fmt.Errorf("bootstrap HTTP services: %w", err)
	}

	router.Register(engine, svc)

	// ServiceManager.StartHealthChecks predates PluginReconciler and probes
	// any plugin registered via the legacy POST /plugins/register HTTP path.
	// PluginReconciler (PR #57) handles CR-backed plugins; PR2 will share
	// the same *ServiceManager so the two probe loops collapse into one.
	// Until then both run — they touch disjoint registrations.
	pluginCtx, pluginCancel := context.WithCancel(ctx)
	defer pluginCancel()
	go svc.ServiceManager.StartHealthChecks(pluginCtx, 30*time.Second)

	srv := &http.Server{
		Addr:    ":" + r.Cfg.Port,
		Handler: engine,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("HTTP server starting on port %s", r.Cfg.Port)
		log.Printf("PORT env var: %s", os.Getenv("PORT"))
		for _, url := range r.Cfg.GetServerURLs() {
			log.Printf("  %s", url)
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTP server failed: %w", err)
			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("HTTP server shutdown: %w", err)
		}
		log.Println("HTTP server exited")
		return nil
	case err := <-serverErr:
		return err
	}
}

// Compile-time interface checks.
var (
	_ manager.Runnable               = (*Runnable)(nil)
	_ manager.LeaderElectionRunnable = (*Runnable)(nil)
)
