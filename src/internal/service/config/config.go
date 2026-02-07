package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	SettingsPath = "/boot/config/plugins/raidman/settings.json"
)

type Settings struct {
	HostTerminalEnabled bool     `json:"host_terminal_enabled"`
	RestrictApiKeys     bool     `json:"restrict_api_keys"`
	AllowedApiKeys      []string `json:"allowed_api_keys"`
}

var (
	currentSettings *Settings
	settingsMutex   sync.RWMutex
)

func init() {
	// specific default settings
	currentSettings = &Settings{
		HostTerminalEnabled: true,
		RestrictApiKeys:     false,
		AllowedApiKeys:      []string{},
	}
}

func GetSettings() *Settings {
	settingsMutex.RLock()
	defer settingsMutex.RUnlock()
	return currentSettings
}

func LoadSettings() {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()

	defer func() {
		log.Printf("[CONFIG] Loaded Settings: HostTerminal=%v, RestrictKeys=%v, AllowedKeys=%d",
			currentSettings.HostTerminalEnabled,
			currentSettings.RestrictApiKeys,
			len(currentSettings.AllowedApiKeys))
	}()

	if _, err := os.Stat(SettingsPath); os.IsNotExist(err) {
		log.Printf("[CONFIG] No settings file found at %s, using defaults", SettingsPath)
		return
	}

	content, err := os.ReadFile(SettingsPath)
	if err != nil {
		log.Printf("[CONFIG] Error reading settings file: %v", err)
		return
	}

	var newSettings Settings
	if err := json.Unmarshal(content, &newSettings); err != nil {
		log.Printf("[CONFIG] Error parsing settings file: %v", err)
		return
	}

	currentSettings = &newSettings
}

func WatchSettings() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[CONFIG] Error creating watcher: %v", err)
		return
	}

	// Watch the directory because editors might atomic save (rename)
	dir := filepath.Dir(SettingsPath)
	if err := watcher.Add(dir); err != nil {
		log.Printf("[CONFIG] Error watching directory %s: %v", dir, err)
		return
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Name == SettingsPath {
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename {
						log.Println("[CONFIG] Settings file changed, reloading...")
						// Small delay to ensure write complete
						time.Sleep(100 * time.Millisecond)
						LoadSettings()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("[CONFIG] Watcher error:", err)
			}
		}
	}()
}
