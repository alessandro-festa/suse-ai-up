package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	_ "github.com/SUSE/suse-ai-up/docs"
	"github.com/SUSE/suse-ai-up/internal/bootstrap"
	"github.com/SUSE/suse-ai-up/internal/config"
	"github.com/SUSE/suse-ai-up/internal/router"
)

// @title SUSE AI Uniproxy API
// @version 1.0
// @description A comprehensive, modular MCP (Model Context Protocol) proxy system
// @termsOfService http://swagger.io/terms/

// @contact.name SUSE
// @contact.url https://github.com/suse/suse-ai-up
// @contact.email info@suse.ai

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8911
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key

// RunUniproxy starts the SUSE AI Uniproxy service
func RunUniproxy() {
	log.Printf("MAIN FUNCTION STARTED")

	cfg := config.LoadConfig()
	log.Printf("Config loaded: Port=%s", cfg.Port)

	if cfg.AuthMode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			log.Printf("Panic recovered: %s", err)
		} else {
			log.Printf("Panic recovered: %v", recovered)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "An unexpected error occurred",
		})
	}))

	if cfg.OtelEnabled {
		r.Use(otelgin.Middleware("suse-ai-up"))
	}

	ctx := context.Background()
	svc, err := bootstrap.Bootstrap(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to bootstrap services: %v", err)
	}

	router.Register(r, svc)

	pluginCtx, pluginCancel := context.WithCancel(context.Background())
	defer pluginCancel()
	go svc.ServiceManager.StartHealthChecks(pluginCtx, 30*time.Second)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	log.Printf("DEBUG: About to start Gin HTTP server on port %s", cfg.Port)
	go func() {
		log.Printf("DEBUG: Gin server goroutine started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("ERROR: Gin server failed: %v", err)
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	log.Printf("DEBUG: Gin HTTP server created and goroutine started")

	serverURLs := cfg.GetServerURLs()
	log.Printf("Server starting on port %s (from config)", cfg.Port)
	log.Printf("PORT env var: %s", os.Getenv("PORT"))
	log.Printf("Service will be accessible at:")
	for _, url := range serverURLs {
		log.Printf("  %s", url)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func main() {
	RunUniproxy()
}
