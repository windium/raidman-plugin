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
	"raidman/src/internal/service/config"
	"raidman/src/internal/service/docker"
	"raidman/src/internal/service/system"
	"raidman/src/internal/service/vm"
	"regexp"
)

var validNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

func isValidSafeName(name string) bool {
	return validNameRegex.MatchString(name)
}

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
	mux.HandleFunc("/api/vm/action", a.handleVmAction)
	mux.HandleFunc("/api/system/action", a.handleSystemAction)
	mux.HandleFunc("/api/array/action", a.handleArrayAction)

	mux.HandleFunc("/api/docker/containers", a.handleGetContainers)
	mux.HandleFunc("/api/vms", a.handleGetVms)
	mux.HandleFunc("/api/array/history", a.handleGetParityHistory)

	mux.HandleFunc("/connect", a.handleConnect)

	// NoVNC
	a.registerNoVNC(mux)

	addr := a.ctx.Config.Host + ":" + a.ctx.Config.Port
	log.Printf("Listening on %s", addr)

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

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		if origin == "" {
			return true
		}
		// Check for same origin
		host := r.Host
		if strings.HasPrefix(origin, "http://"+host) || strings.HasPrefix(origin, "https://"+host) {
			return true
		}

		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return true
		}

		log.Printf("[SECURITY] WS Blocked Origin: %s", origin)
		return false
	},
}

func (a *Api) handleConnect(w http.ResponseWriter, r *http.Request) {

	protocolKey := r.Header.Get("Sec-WebSocket-Protocol")

	clientKey := ""
	if auth.IsValidKey(protocolKey) {
		clientKey = protocolKey
	} else {

		clientKey = getAuthKey(r)
	}

	if !auth.IsValidKey(clientKey) {
		// Critical: Log auth failure
		log.Printf("[SECURITY] Unauthorized WS access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get connection type for permission validation
	connType := r.URL.Query().Get("type")

	var permErr error
	switch connType {
	case "array-status":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelRead, domain.PermResourceArray, domain.PermActionRead)
	case "docker-stats":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelRead, domain.PermResourceDocker, domain.PermActionRead)
	case "vm-vnc":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelPrivileged, "vnc", "access")
	case "host":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelPrivileged, "terminal", "access")
	case "docker":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelPrivileged, domain.PermResourceDocker, domain.PermActionAll)
	case "vm":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelPrivileged, domain.PermResourceVM, domain.PermActionAll)
	case "vm-log":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelRead, domain.PermResourceVM, domain.PermActionRead)
	case "docker-log":
		permErr = auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelRead, domain.PermResourceDocker, domain.PermActionRead)
	default:
		http.Error(w, "Unknown connection type", http.StatusBadRequest)
		return
	}

	if permErr != nil {
		log.Printf("Permission denied for %s from %s: %v", connType, r.RemoteAddr, permErr)
		http.Error(w, fmt.Sprintf("Permission denied: %v", permErr), http.StatusForbidden)
		return
	}

	responseHeader := http.Header{}
	if protocolKey != "" {
		responseHeader.Add("Sec-WebSocket-Protocol", protocolKey)
	}

	c, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

	// 3. Handle specific connection type
	switch connType {
	case "array-status":
		a.handleArrayStream(c)
	case "docker-stats":
		containerID := r.URL.Query().Get("container")
		a.handleDockerStatsStream(c, containerID)
	case "vm-vnc":
		vmName := r.URL.Query().Get("vm")
		if !isValidSafeName(vmName) {
			c.WriteMessage(websocket.TextMessage, []byte("Error: invalid vm name"))
			return
		}
		a.handleVncProxy(c, vmName)
	case "host", "docker", "vm", "vm-log", "docker-log":
		a.handlePty(c, connType, r)
	default:

		log.Printf("Unknown connection type: %s", connType)
		c.WriteMessage(websocket.TextMessage, []byte("Error: unknown type"))
	}
}

func (a *Api) handleArrayStream(c *websocket.Conn) {
	log.Println("Starting Array Status Stream")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Error creating fsnotify watcher: %v", err)
		return
	}
	defer watcher.Close()

	watchDir := "/var/local/emhttp"
	// Verify directory exists (fallback for dev)
	if _, err := os.Stat(watchDir); err == nil {
		if err := watcher.Add(watchDir); err != nil {
			log.Printf("Error adding watch to %s: %v", watchDir, err)
		} else {
			log.Printf("Watching %s for changes", watchDir)
		}
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// State for Speed Calculation
	var prevStatus *domain.ArrayStatus
	var lastUpdate time.Time
	var lastBroadcast time.Time

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

		// Update state
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

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Filter for relevant files
			name := filepath.Base(event.Name)
			if name == "var.ini" || name == "disks.ini" || name == "devs.ini" {
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename {

					broadcast()
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("Watcher error:", err)

		case <-ticker.C:

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

			continue
		}

		if len(stats) > 0 {
			if containerID != "" {

				if err := c.WriteJSON(stats[0]); err != nil {
					return
				}
			} else {

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

	if !isValidSafeName(vmName) {
		c.WriteMessage(websocket.TextMessage, []byte("Error: invalid vm name"))
		return
	}

	port, err := vm.GetVncPort(vmName)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error finding VNC port: "+err.Error()))
		return
	}

	vncConn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error connecting to VNC: "+err.Error()))
		return
	}
	defer vncConn.Close()

	// Proxy WebSocket <-> TCP
	errChan := make(chan error, 2)

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

	<-errChan
}

func (a *Api) handlePty(c *websocket.Conn, termType string, r *http.Request) {
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		clientKey = "unknown"
	}
	log.Printf("[AUDIT] Starting PTY session '%s' by key %s", termType, maskedKey(clientKey))

	var cmd *exec.Cmd

	switch termType {
	case "host":
		// Check config first
		settings := config.GetSettings()
		if !settings.HostTerminalEnabled {
			log.Printf("[SECURITY] Host terminal disabled by settings")
			c.WriteMessage(websocket.TextMessage, []byte("Error: Host terminal access is disabled by administrator"))
			return
		}

		cmd = exec.Command("/bin/bash")
		cmd.Env = append(os.Environ(), "TERM=xterm")

	case "docker":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		if !isValidSafeName(containerID) {
			c.WriteMessage(websocket.TextMessage, []byte("Error: invalid container id"))
			return
		}
		cmd = exec.Command("docker", "exec", "-it", containerID, "sh")

	case "vm": // Serial Console
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		if !isValidSafeName(vmName) {
			c.WriteMessage(websocket.TextMessage, []byte("Error: invalid vm name"))
			return
		}
		cmd = exec.Command("virsh", "console", vmName)
	case "vm-log":

		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		if !isValidSafeName(vmName) {
			c.WriteMessage(websocket.TextMessage, []byte("Error: invalid vm name"))
			return
		}

		logPath := fmt.Sprintf("/var/log/libvirt/qemu/%s.log", vmName)
		cmd = exec.Command("tail", "-f", "-n", "100", logPath)

	case "docker-log":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			c.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		if !isValidSafeName(containerID) {
			c.WriteMessage(websocket.TextMessage, []byte("Error: invalid container id"))
			return
		}
		cmd = exec.Command("docker", "logs", "-f", "--tail", "100", containerID)
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		c.WriteMessage(websocket.TextMessage, []byte("Error starting pty: "+err.Error()))
		return
	}
	defer func() { _ = ptmx.Close() }()

	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {

				ptmx.Close()
				return
			}
			ptmx.Write(message)
		}
	}()

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

func getAuthKey(r *http.Request) string {

	key := r.Header.Get("x-api-key")
	if key != "" {
		return key
	}

	if cookie, err := r.Cookie("x-api-key"); err == nil {
		return cookie.Value
	}

	if cookie, err := r.Cookie("raidman_session"); err == nil {
		return cookie.Value
	}

	return ""
}

func maskedKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "***" + key[len(key)-4:]
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
	// Use strict regex validation instead of weak replacement
	if !isValidSafeName(iconName) {
		http.Error(w, "Invalid icon name", http.StatusBadRequest)
		return
	}

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
	clientKey := getAuthKey(r)

	// Validate permissions
	if err := auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelWrite, domain.PermResourceDocker, domain.PermActionUpdate); err != nil {
		log.Printf("Permission denied for Docker action: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
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

	if req.Container == "" {
		http.Error(w, "Invalid params", http.StatusBadRequest)
		return
	}

	// We delegate validation to the service, or validate here loosely.
	// Service whitelist is safer.
	// Allow any non-empty action string to pass to service which has whitelist.
	if req.Action == "" {
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}

	if err := docker.ExecuteContainerAction(req.Container, req.Action); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] Docker Action '%s' on container '%s' by key %s", req.Action, req.Container, maskedKey(clientKey))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *Api) handleSystemAction(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)

	// Validate permissions (system actions require ADMIN)
	if err := auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelAdmin, domain.PermResourceSystem, domain.PermActionAll); err != nil {
		log.Printf("Permission denied for System action: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action string `json:"action"` // shutdown, reboot
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Action == "" || (req.Action != "shutdown" && req.Action != "reboot") {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err := system.ExecuteAction(req.Action); err != nil {
		log.Printf("[AUDIT] System Action '%s' FAILED by key %s: %v", req.Action, maskedKey(clientKey), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] System Action '%s' executed by key %s", req.Action, maskedKey(clientKey))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

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

func (a *Api) handleGetContainers(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	containers, err := docker.GetContainers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(containers)
}

func (a *Api) handleGetVms(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vms, err := vm.GetVms()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vms)
}

func (a *Api) handleGetParityHistory(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)
	if !auth.IsValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	history, err := array.GetParityHistory()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func (a *Api) handleVmAction(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)

	// Validate permissions
	if err := auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelWrite, domain.PermResourceVM, domain.PermActionUpdate); err != nil {
		log.Printf("Permission denied for VM action: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Vm     string `json:"vm"`
		Action string `json:"action"` // start, stop, pause, resume...
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Vm == "" || req.Action == "" {
		http.Error(w, "Missing params", http.StatusBadRequest)
		return
	}

	if err := vm.ExecuteVmAction(req.Vm, req.Action); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] VM Action '%s' on '%s' by key %s", req.Action, req.Vm, maskedKey(clientKey))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *Api) handleArrayAction(w http.ResponseWriter, r *http.Request) {
	clientKey := getAuthKey(r)

	// Validate permissions (Write Access to Array)
	if err := auth.ValidateSecurityLevel(clientKey, domain.SecurityLevelWrite, domain.PermResourceArray, domain.PermActionUpdate); err != nil {
		log.Printf("Permission denied for Array action: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action string `json:"action"` // spinup, spindown
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Action == "" {
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}

	if err := array.ExecuteAction(req.Action); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
