package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"

	"raidman/src/internal/domain"
	"raidman/src/internal/service/array"
	"raidman/src/internal/service/auth"
	"raidman/src/internal/service/docker"
	"raidman/src/internal/service/vm"
	"raidman/src/internal/web"
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
	mux.HandleFunc("/api/vm/info", a.handleVmInfo)
	mux.HandleFunc("/api/vm/autostart", a.handleVmAutostart)
	mux.HandleFunc("/api/vm/icon", a.handleVmIcon)
	mux.HandleFunc("/api/array/status", a.handleArrayStatus)
	mux.HandleFunc("/api/docker/action", a.handleContainerAction)

	// Push APIs
	// mux.HandleFunc("/api/push/token", a.handlePushTokenRegister)
	// mux.HandleFunc("/api/internal/push", a.handleInternalPush)

	// WebSocket
	mux.HandleFunc("/connect", a.handleConnect)

	// Static files
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/terminal", a.handleIndex) // Alias for terminal

	// NoVNC
	a.registerNoVNC(mux)

	addr := a.ctx.Config.Host + ":" + a.ctx.Config.Port
	log.Printf("Listening on %s", addr)

	// Middleware to strip /raidman prefix if present
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raidman") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/raidman")
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		mux.ServeHTTP(w, r)
	})

	return http.ListenAndServe(addr, handler)
}

// ... (getAuthKey is unchanged) ...

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (app, localhost, etc)
	},
}

func (a *Api) handleConnect(w http.ResponseWriter, r *http.Request) {
	// 1. Auth (Security Check)
	// Check Sec-WebSocket-Protocol (standard way to pass auth in WS from browser)
	protocolKey := r.Header.Get("Sec-WebSocket-Protocol")

	clientKey := ""
	if auth.IsValidKey(protocolKey) {
		clientKey = protocolKey
	} else {
		// Use generic helper (checks Header AND Cookie)
		clientKey = getAuthKey(r)
	}

	// Fallback 2: Check 'token' query parameter (for standard NoVNC path connection)
	if clientKey == "" {
		clientKey = r.URL.Query().Get("token")
	}

	if !auth.IsValidKey(clientKey) {
		log.Printf("Unauthorized WS access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Upgrade to WebSocket
	responseHeader := http.Header{}
	if protocolKey != "" {
		responseHeader.Add("Sec-WebSocket-Protocol", protocolKey)
	}

	c, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	// Note: We don't defer c.Close() here because handlePty might run in goroutine
	// Actually, standard pattern is blocking handler.
	defer c.Close()

	// 3. Handle specific connection type
	// query params: type=[array-status, vm-vnc, docker-stats, host, docker, etc]
	connType := r.URL.Query().Get("type")

	switch connType {
	case "array-status":
		a.handleArrayStream(c)
	case "docker-stats":
		containerID := r.URL.Query().Get("container")
		a.handleDockerStatsStream(c, containerID)
	case "vm-vnc":
		vmName := r.URL.Query().Get("vm")
		a.handleVncProxy(c, vmName)
	case "host", "docker", "vm", "vm-log", "docker-log":
		a.handlePty(c, connType, r)
	default:
		// Unknown
		log.Printf("Unknown connection type: %s", connType)
		c.WriteMessage(websocket.TextMessage, []byte("Error: unknown type"))
	}
}

func (a *Api) handleArrayStream(c *websocket.Conn) {
	log.Println("Starting Array Status Stream")

	// 1. Setup FS Watcher for INI changes (Reactive to state changes)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Error creating fsnotify watcher: %v", err)
		return
	}
	defer watcher.Close()

	// Watch the directory because Unraid often does Rename/Replace for files
	watchDir := "/var/local/emhttp"
	// Verify directory exists (fallback for dev)
	if _, err := os.Stat(watchDir); err == nil {
		if err := watcher.Add(watchDir); err != nil {
			log.Printf("Error adding watch to %s: %v", watchDir, err)
		} else {
			log.Printf("Watching %s for changes", watchDir)
		}
	}

	// 2. Setup Ticker for Real-time Stats
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// State for Speed Calculation
	var prevStatus *domain.ArrayStatus
	var lastUpdate time.Time
	var lastBroadcast time.Time

	// Helper to broadcast status
	broadcast := func() {
		// Debounce: Only broadcast once per second max
		if time.Since(lastBroadcast) < 900*time.Millisecond {
			return
		}

		status, err := array.GetArrayStatus()
		if err != nil {
			log.Printf("Error getting array status: %v", err)
			return
		}

		now := time.Now()
		if prevStatus != nil {
			delta := now.Sub(lastUpdate).Seconds()
			if delta > 0 {
				array.CalculateSpeeds(status, prevStatus, delta)
			}
		}

		// Update state (copy status? GetArrayStatus returns new struct pointer, so safe to store)
		// However, we effectively store the pointer.
		// Since GetArrayStatus allocates new struct every time, this is safe.
		prevStatus = status
		lastUpdate = now
		lastBroadcast = now

		wrapper := map[string]interface{}{
			"array": map[string]interface{}{
				"state":             status.State,
				"parityCheckStatus": status.ParityCheckStatus,
				"parities":          status.Parities,
				"disks":             status.Disks,
				"caches":            status.Caches,
				"boot":              status.Boot,
				"unassigned":        status.Unassigned,
			},
		}

		if err := c.WriteJSON(wrapper); err != nil {
			return
		}
	}

	// Initial broadcast
	broadcast()

	// Main Loop
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Filter for relevant files
			// Unraid updates often use temp files then rename, so we watch for Write or Rename on target names
			name := filepath.Base(event.Name)
			if name == "var.ini" || name == "disks.ini" || name == "devs.ini" {
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename {
					// Trigger update (Reactive)
					// Verify debounce?
					broadcast()
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Watcher error:", err)

		case <-ticker.C:
			// Regular polling for live stats (diskstats integration)
			broadcast()
		}
	}
}

func (a *Api) handleDockerStatsStream(c *websocket.Conn, containerID string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats, err := docker.GetContainerStats(containerID)
		if err != nil {
			// Container stopped or error?
			continue
		}

		if len(stats) > 0 {
			if containerID != "" {
				// Single object
				if err := c.WriteJSON(stats[0]); err != nil {
					return
				}
			} else {
				// Array
				if err := c.WriteJSON(stats); err != nil {
					return
				}
			}
		}
	}
}

func (a *Api) handleVncProxy(c *websocket.Conn, vmName string) {
	if vmName == "" {
		c.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
		return
	}

	port, err := vm.GetVncPort(vmName)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error finding VNC port: "+err.Error()))
		return
	}

	// Connect to VNC server on localhost
	vncConn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error connecting to VNC: "+err.Error()))
		return
	}
	defer vncConn.Close()

	// Proxy WebSocket <-> TCP
	errChan := make(chan error, 2)

	// WS -> TCP
	go func() {
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if _, err := vncConn.Write(msg); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// TCP -> WS
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := vncConn.Read(buf)
			if n > 0 {
				if err := c.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Wait for closing
	<-errChan
}

func (a *Api) handlePty(c *websocket.Conn, termType string, r *http.Request) {
	var cmd *exec.Cmd

	switch termType {
	case "host":
		cmd = exec.Command("/bin/bash")
		cmd.Env = append(os.Environ(), "TERM=xterm")

	case "docker":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		cmd = exec.Command("docker", "exec", "-it", containerID, "sh")

	case "vm": // Serial Console
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		cmd = exec.Command("virsh", "console", vmName)

	case "vm-log": // VM Logs
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		// Location for logs in Unraid/Libvirt
		logPath := fmt.Sprintf("/var/log/libvirt/qemu/%s.log", vmName)
		cmd = exec.Command("tail", "-f", "-n", "100", logPath)

	case "docker-log":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		cmd = exec.Command("docker", "logs", "-f", "--tail", "100", containerID)
	}

	// PTY Execution
	ptmx, err := pty.Start(cmd)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error starting pty: "+err.Error()))
		return
	}
	defer func() { _ = ptmx.Close() }()

	// WS -> PTY
	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				return
			}
			ptmx.Write(message)
		}
	}()

	// PTY -> WS
	buf := make([]byte, 1024)
	for {
		n, err := ptmx.Read(buf)
		if err != nil {
			break
		}
		err = c.WriteMessage(websocket.BinaryMessage, buf[:n])
		if err != nil {
			break
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
		// Fallback to embedded version
		log.Printf("Could not read index.html from filesystem, using embedded version: %v", err)
		indexData, err = web.IndexFS.ReadFile("index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
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

func (a *Api) handleVmAutostart(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Vm      string `json:"vm"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Vm == "" {
		http.Error(w, "Missing vm name", http.StatusBadRequest)
		return
	}

	if err := vm.SetVmAutostart(req.Vm, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *Api) handleVmIcon(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	iconName := r.URL.Query().Get("icon")
	if iconName == "" {
		http.Error(w, "Missing icon param", http.StatusBadRequest)
		return
	}

	// Sanitize filename
	iconName = strings.ReplaceAll(iconName, "..", "")
	iconName = strings.ReplaceAll(iconName, "/", "")

	// Unraid VM icon path
	iconPath := fmt.Sprintf("/usr/local/emhttp/plugins/dynamix.vm.manager/templates/images/%s", iconName)

	if _, err := os.Stat(iconPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, iconPath)
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

func (a *Api) handleContainerAction(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Container string `json:"container"`
		Action    string `json:"action"` // pause, unpause
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Container == "" || (req.Action != "pause" && req.Action != "unpause") {
		http.Error(w, "Invalid params", http.StatusBadRequest)
		return
	}

	if err := docker.ExecuteContainerAction(req.Container, req.Action); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/*
func (a *Api) handlePushTokenRegister(w http.ResponseWriter, r *http.Request) {
    // ... removed ...
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *Api) handleInternalPush(w http.ResponseWriter, r *http.Request) {
    // ... removed ...
}
*/

func (a *Api) registerNoVNC(mux *http.ServeMux) {
	// Full NoVNC Static Files
	novncPath := "/usr/local/emhttp/plugins/raidman/web/novnc"
	if _, err := os.Stat(novncPath); os.IsNotExist(err) {
		log.Printf("WARNING: noVNC directory not found at %s", novncPath)
	} else {
		log.Printf("Serving noVNC from: %s", novncPath)
	}

	novncFS := http.Dir(novncPath)
	outputFS := http.FileServer(novncFS)
	strippedHandler := http.StripPrefix("/novnc/", outputFS)

	mux.Handle("/novnc/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := getAuthKey(r)
		validKey := auth.IsValidKey(clientKey)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			return
		}

		if !validKey {
			log.Printf("Unauthorized NoVNC access attempt from %s (path: %s)", r.RemoteAddr, r.URL.Path)
			http.Error(w, "Unauthorized: Valid x-api-key header or cookie required", http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "raidman_session",
			Value:    clientKey,
			Path:     "/raidman/",
			MaxAge:   3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		strippedHandler.ServeHTTP(w, r)
	}))
}
