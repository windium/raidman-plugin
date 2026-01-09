package main

import (
	"log"

	"raidman/src/internal/domain"
	"raidman/src/internal/service"
)

var Version = "1.0.0"

func main() {
	// Initialize Context
	ctx := &domain.Context{
		Config: domain.Config{
			Version: Version,
		},
	}

	// Create and Run Orchestrator
	orchestrator := service.CreateOrchestrator(ctx)
	if err := orchestrator.Run(); err != nil {
		log.Fatalf("Error running orchestrator: %v", err)
	}
}
