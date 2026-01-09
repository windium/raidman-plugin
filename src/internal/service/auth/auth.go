package auth

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"

	"raidman/src/internal/domain"
)

var (
	validKeys = make(map[string]bool)
	keysMutex sync.RWMutex
)

func LoadApiKeys() {
	keysMutex.Lock()
	defer keysMutex.Unlock()

	// Handle case where path doesn't exist (local dev)
	if _, err := os.Stat(domain.KeysPath); os.IsNotExist(err) {
		log.Printf("Warning: Keys directory %s does not exist", domain.KeysPath)
		return
	}

	files, err := os.ReadDir(domain.KeysPath)
	if err != nil {
		log.Printf("Warning: Could not read keys directory: %v", err)
		return
	}

	// Reset valid keys
	validKeys = make(map[string]bool)

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			content, err := os.ReadFile(filepath.Join(domain.KeysPath, file.Name()))
			if err != nil {
				continue
			}

			var apiKey domain.ApiKeyStruct
			if err := json.Unmarshal(content, &apiKey); err == nil && apiKey.Key != "" {
				validKeys[apiKey.Key] = true
			}
		}
	}
	log.Printf("Loaded %d valid API keys", len(validKeys))
}

func IsValidKey(key string) bool {
	keysMutex.RLock()
	defer keysMutex.RUnlock()
	return validKeys[key]
}
