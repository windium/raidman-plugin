package service

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"raidman/src/internal/api"
	"raidman/src/internal/domain"
	"raidman/src/internal/service/auth"
	"raidman/src/internal/service/notification"
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

	// Load Push Tokens
	notification.LoadTokens()

	// Load API Keys
	auth.LoadApiKeys()

	// Initialize API Server
	// We pass the context so API knows about config
	server := api.Create(o.ctx)

	// Start API
	// server.Run() should be blocking or non-blocking?
	// Usually http.ListenAndServe is blocking.
	// So we should run it in a goroutine if we want to listen for signals here.

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
