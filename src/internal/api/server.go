package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"raidman/src/internal/domain"
	"raidman/src/internal/service/array"
	"raidman/src/internal/service/auth"
	"raidman/src/internal/service/notification"
	"raidman/src/internal/service/vm"
)

type Api struct {
	ctx *domain.Context
}

func Create(ctx *domain.Context) *Api {
	return &Api{
		ctx: ctx,
	}
}

func (a *Api) Run() error {
	mux := http.NewServeMux()

	// Register Routes
	mux.HandleFunc("/api/vm", a.handleVmInfo)
	mux.HandleFunc("/api/array/status", a.handleArrayStatus)
	mux.HandleFunc("/api/push/register", a.handlePushTokenRegister)
	mux.HandleFunc("/api/push/send", a.handleInternalPush)

	// WebSocket
	mux.HandleFunc("/connect", a.handleConnect)

	// Static files
	mux.HandleFunc("/", a.handleIndex)

	port := ":2378"
	log.Printf("Listening on %s", port)
	return http.ListenAndServe(port, mux)
}

// ... (getAuthKey is unchanged) ...

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (app, localhost, etc)
	},
}

func (a *Api) handleConnect(w http.ResponseWriter, r *http.Request) {
	// 1. Auth
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Upgrade to WebSocket
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Gorilla returns 400 Bad Request automatically on handshake fail,
		// but we can log it.
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

	// 3. Handle specific connection type
	// query params: type=[array-status, vm-vnc, docker-stats]
	connType := r.URL.Query().Get("type")

	if connType == "array-status" {
		a.handleArrayStream(c)
	} else {
		// Unknown or unsupported type for now
		log.Printf("Unknown connection type: %s", connType)
	}
}

func (a *Api) handleArrayStream(c *websocket.Conn) {
	log.Println("Starting Array Status Stream")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			status, err := array.GetArrayStatus()
			if err != nil {
				log.Printf("Error getting array status: %v", err)
				continue
			}

			// Wrap in object expecting "array" key as per client
			resp := map[string]interface{}{
				"array": status,
			}

			if err := c.WriteJSON(resp); err != nil {
				log.Println("write:", err)
				return // break loop and close connection
			}
		}
	}
}

// Helper: Get API Key from Header OR Cookie
func getAuthKey(r *http.Request) string {
	// 1. Check Header
	key := r.Header.Get("x-api-key")
	if key != "" {
		return key
	}

	// 2. Check Cookie "x-api-key"
	if cookie, err := r.Cookie("x-api-key"); err == nil {
		return cookie.Value
	}

	// 3. Check Cookie "raidman_session" (Legacy/Session fallback)
	if cookie, err := r.Cookie("raidman_session"); err == nil {
		return cookie.Value
	}

	return ""
}

func (a *Api) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 1. Validate API Key from Header or Cookie
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		log.Printf("Unauthorized index access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized: Valid x-api-key header required", http.StatusUnauthorized)
		return
	}

	// 2. Try to read index.html from filesystem first
	indexPath := "/usr/local/emhttp/plugins/raidman/web/index.html"
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		log.Printf("Could not read index.html from filesystem: %v", err)
		http.Error(w, "Index file not found", http.StatusInternalServerError)
		return
	}

	// Simple string replacement to inject the key securely into JS
	htmlContent := string(indexData)
	htmlContent = strings.Replace(htmlContent, "{{API_KEY}}", clientKey, 1)

	// Prevent caching of the page containing the sensitive key
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

func (a *Api) handleVmInfo(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vmName := r.URL.Query().Get("vm")
	if vmName == "" {
		http.Error(w, "Missing vm param", http.StatusBadRequest)
		return
	}

	info, err := vm.GetVmInfo(vmName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (a *Api) handleArrayStatus(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	status, err := array.GetArrayStatus()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting status: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (a *Api) handlePushTokenRegister(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req domain.PushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	notification.RegisterToken(req.Token)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *Api) handleInternalPush(w http.ResponseWriter, r *http.Request) {
	// Localhost only security check
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		log.Printf("Internal push rejected: non-localhost request from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req domain.InternalPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	count := notification.BroadcastNotification(req)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"devices": count,
	})
}
