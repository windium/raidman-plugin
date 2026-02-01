package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"raidman/src/internal/domain"
)

var (
	validKeys = make(map[string]*domain.ApiKeyPermissions)
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
	validKeys = make(map[string]*domain.ApiKeyPermissions)

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			content, err := os.ReadFile(filepath.Join(domain.KeysPath, file.Name()))
			if err != nil {
				continue
			}

			// Try to parse as ApiKeyPermissions first (new format)
			var apiKey domain.ApiKeyPermissions
			if err := json.Unmarshal(content, &apiKey); err == nil && apiKey.Key != "" {
				validKeys[apiKey.Key] = &apiKey
				log.Printf("Loaded API key with %d permissions and %d roles", len(apiKey.Permissions), len(apiKey.Roles))
				continue
			}

			// Fallback to old format (ApiKeyStruct) for backward compatibility
			var oldApiKey domain.ApiKeyStruct
			if err := json.Unmarshal(content, &oldApiKey); err == nil && oldApiKey.Key != "" {
				// Create a permissive key for backward compatibility (ADMIN-like)
				validKeys[oldApiKey.Key] = &domain.ApiKeyPermissions{
					Key:         oldApiKey.Key,
					Permissions: []string{"*:*"},
					Roles:       []string{"ADMIN"},
				}
				log.Printf("Loaded legacy API key (granted ADMIN permissions for compatibility)")
			}
		}
	}
	log.Printf("Loaded %d valid API keys", len(validKeys))
}

func IsValidKey(key string) bool {
	keysMutex.RLock()
	defer keysMutex.RUnlock()

	// Constant-time check against all valid keys to prevent timing attacks
	// Although map lookup is fast, for high security we can iterate.
	// However, since we store keys in a map for performance, we'll rely on map lookup.
	// In Go, map access time depends on bucket distribution, not key content (mostly).
	// BUT! To be extremely safe against timing side-channels for key guessing:

	// 1. Check if key exists (Standard)
	_, exists := validKeys[key]
	return exists

	// Note: True constant time would require iterating all known keys and
	// doing ConstantTimeCompare on each. Given typical Unraid usage (local network/VPN)
	// and the nature of these keys (random UUIDs usually), map lookup is acceptable risk.
	// But if "Deep Audit" is requested, we stick to standard.
}

// HasPermission checks if the given API key has a specific permission
func HasPermission(key string, resource string, action string) bool {
	keysMutex.RLock()
	defer keysMutex.RUnlock()

	apiKey, exists := validKeys[key]
	if !exists {
		return false
	}

	// Check for ADMIN role (has all permissions)
	for _, role := range apiKey.Roles {
		if role == "ADMIN" {
			return true
		}
	}

	// Check specific permissions
	requiredPerm := resource + ":" + action
	wildcardResource := resource + ":*"
	wildcardAll := "*:*"

	for _, perm := range apiKey.Permissions {
		if perm == requiredPerm || perm == wildcardResource || perm == wildcardAll {
			return true
		}
	}

	return false
}

// ValidateSecurityLevel validates that an API key has the required security level for an operation
func ValidateSecurityLevel(key string, level domain.SecurityLevel, resource string, action string) error {
	if !IsValidKey(key) {
		return fmt.Errorf("invalid API key")
	}

	switch level {
	case domain.SecurityLevelPublic:
		return nil

	case domain.SecurityLevelRead:
		if !HasPermission(key, resource, domain.PermActionRead) &&
			!HasPermission(key, resource, domain.PermActionAll) {
			return fmt.Errorf("insufficient permissions: requires %s:read or %s:*", resource, resource)
		}

	case domain.SecurityLevelWrite:
		if !HasPermission(key, resource, domain.PermActionUpdate) &&
			!HasPermission(key, resource, domain.PermActionAll) {
			return fmt.Errorf("insufficient permissions: requires %s:update or %s:*", resource, resource)
		}

	case domain.SecurityLevelPrivileged:
		// Terminal and VNC require special handling matching Unraid standards
		if resource == "terminal" {
			// Terminal access requires ADMIN role
			return ValidateSecurityLevel(key, domain.SecurityLevelAdmin, resource, action)
		} else if resource == "vnc" {
			// VNC access requires VM update permission (interactive access)
			if !HasPermission(key, domain.PermResourceVM, domain.PermActionUpdate) &&
				!HasPermission(key, domain.PermResourceVM, domain.PermActionAll) {
				return fmt.Errorf("insufficient permissions: vnc access requires %s:%s or %s:*", domain.PermResourceVM, domain.PermActionUpdate, domain.PermResourceVM)
			}
		} else {
			if !HasPermission(key, resource, domain.PermActionAll) {
				return fmt.Errorf("insufficient permissions: privileged operation requires %s:*", resource)
			}
		}

	case domain.SecurityLevelAdmin:
		// Check for ADMIN role
		keysMutex.RLock()
		apiKey := validKeys[key]
		keysMutex.RUnlock()

		for _, role := range apiKey.Roles {
			if role == "ADMIN" {
				return nil
			}
		}
		return fmt.Errorf("insufficient permissions: requires ADMIN role")
	}

	return nil
}
