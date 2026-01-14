package service

import (
	"log"
	"mime"
	"os"
	"os/signal"
	"syscall"
	"time"

	"raidman/src/internal/api"
	"raidman/src/internal/domain"
	"raidman/src/internal/service/auth"
)

type Orchestrator struct {
	ctx *domain.Context
}

func CreateOrchestrator(ctx *domain.Context) *Orchestrator {
	return &Orchestrator{
		ctx: ctx,
	}
}

func (o *Orchestrator) Run() error {
	log.Printf("Starting Raidman Plugin (Version: %s)...", o.ctx.Config.Version)

	// Load API Keys
	auth.LoadApiKeys()

	// Fix MIME types (as per original main.go)
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".mjs", "application/javascript")
	mime.AddExtensionType(".html", "text/html")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".wasm", "application/wasm")

	// Initialize API Server
	// We pass the context so API knows about config
	server := api.Create(o.ctx)

	// Periodically reload keys
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			auth.LoadApiKeys()
		}
	}()

	// Start API
	go func() {
		if err := server.Run(); err != nil {
			log.Fatalf("API Server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	w := make(chan os.Signal, 1)
	signal.Notify(w, syscall.SIGTERM, syscall.SIGINT)
	log.Printf("Received %s signal. Shutting down...", <-w)

	return nil
}
