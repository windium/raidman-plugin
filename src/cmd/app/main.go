package main

import (
	"flag"
	"log"

	"raidman/src/internal/domain"
	"raidman/src/internal/service"
)

var Version = "1.0.0"

func main() {
	port := flag.String("port", "9876", "Port to listen on")
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	flag.Parse()

	// Initialize Context
	ctx := &domain.Context{
		Config: domain.Config{
			Version: Version,
			Host:    *host,
			Port:    *port,
		},
	}

	// Create and Run Orchestrator
	orchestrator := service.CreateOrchestrator(ctx)
	if err := orchestrator.Run(); err != nil {
		log.Fatalf("Error running orchestrator: %v", err)
	}
}
