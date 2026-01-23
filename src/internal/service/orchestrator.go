package service

import (
	"log"
	"mime"
	"os"
	"os/signal"
	"syscall"

	"raidman/src/internal/api"
	"raidman/src/internal/domain"
	"raidman/src/internal/service/auth"

	"github.com/fsnotify/fsnotify"
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

	// Watch for API Key changes (Reactive)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Error creating fsnotify watcher for keys: %v", err)
	} else {
		defer watcher.Close()

		// Add Watch
		keysPath := domain.KeysPath
		// Check if exists first
		if _, err := os.Stat(keysPath); os.IsNotExist(err) {
			log.Printf("Keys directory %s does not exist, skipping watch", keysPath)
		} else {
			if err := watcher.Add(keysPath); err != nil {
				log.Printf("Error watching keys path: %v", err)
			} else {
				log.Printf("Watching %s for API Key changes", keysPath)
			}
		}

		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					// Check for relevant file events
					if event.Op&fsnotify.Write == fsnotify.Write ||
						event.Op&fsnotify.Create == fsnotify.Create ||
						event.Op&fsnotify.Remove == fsnotify.Remove ||
						event.Op&fsnotify.Rename == fsnotify.Rename {

						// Reload keys
						// Debounce slightly? Usually not needed for simple key file drops.
						log.Println("Key directory changed, reloading keys...")
						auth.LoadApiKeys()
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Println("Key Watcher error:", err)
				}
			}
		}()
	}

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
