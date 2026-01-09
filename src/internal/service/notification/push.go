package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"raidman/src/internal/domain"
)

var (
	pushTokens = make(map[string]int64) // token -> timestamp
	pushMutex  sync.RWMutex
)

// LoadTokens loads tokens from disk. Should be called at startup.
func LoadTokens() {
	pushMutex.Lock()
	defer pushMutex.Unlock()

	content, err := os.ReadFile(domain.PushTokensPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error reading push tokens: %v", err)
		}
		return
	}

	if err := json.Unmarshal(content, &pushTokens); err != nil {
		log.Printf("Error parsing push tokens: %v", err)
	}
	log.Printf("Loaded %d push tokens", len(pushTokens))
}

func SaveTokens() {
	pushMutex.RLock()
	data, err := json.MarshalIndent(pushTokens, "", "  ")
	pushMutex.RUnlock()

	if err != nil {
		log.Printf("Error marshalling push tokens: %v", err)
		return
	}

	if err := os.WriteFile(domain.PushTokensPath, data, 0644); err != nil {
		log.Printf("Error saving push tokens: %v", err)
	}
}

func RegisterToken(token string) {
	pushMutex.Lock()
	pushTokens[token] = time.Now().Unix()
	pushMutex.Unlock()

	SaveTokens()
}

func BroadcastNotification(req domain.InternalPushRequest) int {
	log.Printf("Received Notification from Unraid: %s - %s", req.Subject, req.Description)

	pushMutex.RLock()
	tokenCount := len(pushTokens)
	var messages []domain.ExpoPushMessage
	for token := range pushTokens {
		// Basic Filter
		if len(token) > 10 {
			msg := domain.ExpoPushMessage{
				To:       token,
				Title:    fmt.Sprintf("Unraid: %s", req.Subject),
				Body:     req.Description,
				Subtitle: req.Event,
				Sound:    "default",
				Data: map[string]interface{}{
					"link":     req.Link,
					"severity": req.Severity,
					"event":    req.Event,
				},
			}
			messages = append(messages, msg)
		}
	}
	pushMutex.RUnlock()

	log.Printf("Broadcasting notification to %d registered devices (total tokens: %d)", len(messages), tokenCount)

	// Async send
	go SendExpoPush(messages)

	return len(messages)
}

func SendExpoPush(messages []domain.ExpoPushMessage) {
	if len(messages) == 0 {
		return
	}

	jsonData, err := json.Marshal(messages)
	if err != nil {
		log.Printf("Error marshalling expo push: %v", err)
		return
	}

	resp, err := http.Post("https://exp.host/--/api/v2/push/send", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error sending push to Expo: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Expo response: %v", err)
		return
	}

	log.Printf("Expo API response (HTTP %d): %s", resp.StatusCode, string(body))
}
