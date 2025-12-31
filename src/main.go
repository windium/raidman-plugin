package main

import (
	"embed"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// Constants
const (
	KeysPath = "/boot/config/plugins/dynamix.my.servers/keys"
)

// Embed the web directory
//
//go:embed web/*
var content embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // CORS allowed, but we validate API Key
	},
}

// Store valid keys in memory
var (
	validKeys = make(map[string]bool)
	keysMutex sync.RWMutex
)

type ApiKeyStruct struct {
	Key string `json:"key"`
}

// XML Structures for parsing virsh dumpxml
type DomainXml struct {
	DeviceList Devices `xml:"devices"`
}

type Devices struct {
	Disks      []Disk      `xml:"disk"`
	Interfaces []Interface `xml:"interface"`
	Graphics   []Graphics  `xml:"graphics"`
}

type Disk struct {
	Type   string     `xml:"type,attr"`
	Device string     `xml:"device,attr"`
	Source DiskSource `xml:"source"`
	Target DiskTarget `xml:"target"`
	Serial string     `xml:"serial"`
	Boot   *DiskBoot  `xml:"boot"`
}

type DiskSource struct {
	File string `xml:"file,attr"`
	Dev  string `xml:"dev,attr"` // for block devices
}

type DiskTarget struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

type DiskBoot struct {
	Order int `xml:"order,attr"`
}

type Interface struct {
	Mac    MacAddress      `xml:"mac"`
	Source InterfaceSource `xml:"source"`
	Model  InterfaceModel  `xml:"model"`
}

type MacAddress struct {
	Address string `xml:"address,attr"`
}

type InterfaceSource struct {
	Bridge string `xml:"bridge,attr"`
	Dev    string `xml:"dev,attr"` // for direct/macvtap
}

type InterfaceModel struct {
	Type string `xml:"type,attr"`
}

type Graphics struct {
	Type     string `xml:"type,attr"`
	Port     int    `xml:"port,attr"`
	AutoPort string `xml:"autoport,attr"`
}

// JSON Output Structures
type VmDisk struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Bus       string `json:"bus"`
	Type      string `json:"type"`
	Serial    string `json:"serial"`
	BootOrder int    `json:"bootOrder"`
}

type VmInterface struct {
	Mac       string `json:"mac"`
	Model     string `json:"model"`
	Network   string `json:"network"`
	IpAddress string `json:"ipAddress"`
}

type VmGraphics struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

// Helper to get IP
func getVmIp(vmName string, mac string) string {
	// Try virsh domifaddr --source agent
	out, err := exec.Command("virsh", "domifaddr", vmName, "--source", "agent").Output()
	if err == nil {
		// Parse output to find IP for this MAC (simplified for now, usually returns first IP)
		// Output format:
		// Name       MAC address          Protocol     Address
		// -------------------------------------------------------------------------------
		// eth0       52:54:00:12:34:56    ipv4         192.168.1.50/24
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(mac)) {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					return strings.Split(fields[3], "/")[0] // Return IP without CIDR
				}
			}
		}
	}
	return ""
}

func getVmDetailsXml(vmName string) (*DomainXml, error) {
	out, err := exec.Command("virsh", "dumpxml", vmName).Output()
	if err != nil {
		return nil, err
	}
	var dom DomainXml
	if err := xml.Unmarshal(out, &dom); err != nil {
		return nil, err
	}
	return &dom, nil
}

type VmInfo struct {
	Name          string        `json:"name"`
	DomId         string        `json:"domId"`
	Uuid          string        `json:"uuid"`
	OsType        string        `json:"osType"`
	DetailedState string        `json:"detailedState"`
	CpuTime       string        `json:"cpuTime"`
	Autostart     bool          `json:"autostart"`
	Memory        int64         `json:"memory"` // in Bytes
	Vcpus         int           `json:"vcpus"`
	Persistent    bool          `json:"persistent"`
	ManagedSave   string        `json:"managedSave"`
	SecurityModel string        `json:"securityModel"`
	SecurityDOI   string        `json:"securityDOI"`
	Description   string        `json:"description"`
	Disks         []VmDisk      `json:"disks"`
	Interfaces    []VmInterface `json:"interfaces"`
	Graphics      []VmGraphics  `json:"graphics"`
}

type AutostartRequest struct {
	Vm      string `json:"vm"`
	Enabled bool   `json:"enabled"`
}

type ArrayStatus struct {
	State string `json:"state"`
	// Basic parity check info
	ParityStatus       string `json:"parityStatus"` // e.g. "RUNNING", "PAUSED", "COMPLETED"
	ParityCheckRunning bool   `json:"parityCheckRunning"`
	ParityTotal        int64  `json:"parityTotal"`
	ParityPos          int64  `json:"parityPos"`
}

func loadApiKeys() {
	keysMutex.Lock()
	defer keysMutex.Unlock()

	// Handle case where path doesn't exist (local dev)
	if _, err := os.Stat(KeysPath); os.IsNotExist(err) {
		// For local testing, add a dummy key if needed or just warn
		log.Printf("Warning: Keys directory %s does not exist", KeysPath)
		return
	}

	files, err := os.ReadDir(KeysPath)
	if err != nil {
		log.Printf("Warning: Could not read keys directory: %v", err)
		return
	}

	// Reset valid keys
	validKeys = make(map[string]bool)

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			content, err := os.ReadFile(filepath.Join(KeysPath, file.Name()))
			if err != nil {
				continue
			}

			var apiKey ApiKeyStruct
			if err := json.Unmarshal(content, &apiKey); err == nil && apiKey.Key != "" {
				validKeys[apiKey.Key] = true
			}
		}
	}
	log.Printf("Loaded %d valid API keys", len(validKeys))
}

func isValidKey(key string) bool {
	keysMutex.RLock()
	defer keysMutex.RUnlock()
	return validKeys[key]
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// 1. Validate API Key from Header (Strict)
	clientKey := r.Header.Get("x-api-key")
	if !isValidKey(clientKey) {
		log.Printf("Unauthorized index access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized: Valid x-api-key header required", http.StatusUnauthorized)
		return
	}

	// 2. Read and Template index.html
	indexData, err := content.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Simple string replacement to inject the key securely into JS
	// We use a placeholder in index.html like {{API_KEY}}
	htmlContent := string(indexData)
	htmlContent = strings.Replace(htmlContent, "{{API_KEY}}", clientKey, 1)

	// Prevent caching of the page containing the sensitive key
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

func parseVncDisplay(display string) (string, error) {
	// 1. Clean up input
	display = strings.TrimSpace(display)

	// 2. Handle "vnc://" prefix (e.g. "vnc://127.0.0.1:0" or "vnc://localhost:0")
	if strings.HasPrefix(display, "vnc://") {
		// Remove "vnc://"
		display = strings.TrimPrefix(display, "vnc://")

		// Unraid/Virsh usually returns host:displayNum.
		// We want the displayNum (part after the last colon).
		lastColon := strings.LastIndex(display, ":")
		if lastColon == -1 {
			return "", fmt.Errorf("invalid vnc URI format (no colon): %s", display)
		}

		// host := display[:lastColon] // we don't need host for local connection usually?
		// Actually for virsh domdisplay, it gives us the display server.
		// But our logic later calculates port 5900 + display.
		// We assume we are connecting to localhost for the VNC proxy usually,
		// BUT wait, getVncPort returns a PORT.
		// And the proxy connects to `127.0.0.1:port`.
		// If virsh says `vnc://some-other-ip:0`, are we supposed to connect to `some-other-ip`?
		// The original code calculated port from `:0` and connected to `127.0.0.1`.
		// So we likely just need the port/display number to connect locally if the VM is local.
		// Unraid VMs run on the host. valid.

		display = display[lastColon:] // includes the colon, e.g. ":0"
	}

	// 3. Handle ":0" format (shorthand)
	if strings.HasPrefix(display, ":") {
		displayNumStr := display[1:]
		var d int
		_, err := fmt.Sscan(displayNumStr, &d)
		if err != nil {
			return "", fmt.Errorf("invalid display number: %s", displayNumStr)
		}
		// Port is 5900 + display
		return fmt.Sprintf("%d", 5900+d), nil
	}

	return "", fmt.Errorf("unknown display format: %s", display)
}

func getVncPort(vmName string) (string, error) {
	// virsh domdisplay returns something like ":0" (for 5900) or "vnc://127.0.0.1:0"
	out, err := exec.Command("virsh", "domdisplay", vmName).Output()
	if err != nil {
		return "", err
	}

	return parseVncDisplay(string(out))
}

func getVmInfo(vmName string) (*VmInfo, error) {
	out, err := exec.Command("virsh", "dominfo", vmName).Output()
	if err != nil {
		return nil, err
	}

	// Parse general info first (existing logic)
	info := &VmInfo{Name: vmName}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Id":
			info.DomId = val
		case "UUID":
			info.Uuid = val
		case "OS Type":
			info.OsType = val
		case "State":
			info.DetailedState = val
		case "CPU(s)":
			fmt.Sscanf(val, "%d", &info.Vcpus)
		case "CPU time":
			info.CpuTime = val
		case "Max memory":
			var memVal int64
			var unit string
			fmt.Sscanf(val, "%d %s", &memVal, &unit)
			if unit == "KiB" {
				info.Memory = memVal * 1024
			} else {
				info.Memory = memVal // Fallback
			}
		case "Persistent":
			info.Persistent = (val == "yes")
		case "Autostart":
			info.Autostart = (val == "enable")
		case "Managed save":
			info.ManagedSave = val
		case "Security model":
			info.SecurityModel = val
		case "Security DOI":
			info.SecurityDOI = val
		}
	}

	// NEW: Parse Detail XML
	xmlDetails, err := getVmDetailsXml(vmName)
	if err == nil && xmlDetails != nil {
		// Populate Disks
		for _, d := range xmlDetails.DeviceList.Disks {
			src := d.Source.File
			if src == "" {
				src = d.Source.Dev
			}
			bootOrder := 0
			if d.Boot != nil {
				bootOrder = d.Boot.Order
			}
			info.Disks = append(info.Disks, VmDisk{
				Source:    src,
				Target:    d.Target.Dev,
				Bus:       d.Target.Bus,
				Type:      d.Type,
				Serial:    d.Serial,
				BootOrder: bootOrder,
			})
		}

		// Populate Interfaces + IPs
		for _, i := range xmlDetails.DeviceList.Interfaces {
			src := i.Source.Bridge
			if src == "" {
				src = i.Source.Dev
			}
			// Fetch IP
			ip := getVmIp(vmName, i.Mac.Address)

			info.Interfaces = append(info.Interfaces, VmInterface{
				Mac:       i.Mac.Address,
				Model:     i.Model.Type,
				Network:   src,
				IpAddress: ip,
			})
		}

		// Populate Graphics
		for _, g := range xmlDetails.DeviceList.Graphics {
			info.Graphics = append(info.Graphics, VmGraphics{
				Type: g.Type,
				Port: g.Port,
			})
		}
	}

	return info, nil
}

func setVmAutostart(vmName string, enabled bool) error {
	args := []string{"autostart", vmName}
	if !enabled {
		args = []string{"autostart", "--disable", vmName}
	}
	return exec.Command("virsh", args...).Run()
}

func getArrayStatus() (*ArrayStatus, error) {
	// 1. Run mdcmd status
	// Check if mdcmd exists
	cmd := exec.Command("/usr/local/sbin/mdcmd", "status")
	if _, err := os.Stat("/usr/local/sbin/mdcmd"); os.IsNotExist(err) {
		// Fallback for dev/testing if not on Unraid
		return &ArrayStatus{State: "STARTED", ParityStatus: "NEVER_RUN", ParityCheckRunning: false}, nil
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	status := &ArrayStatus{
		State:        "UNKNOWN",
		ParityStatus: "NEVER_RUN",
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// mdcmd values are often quoted like "STARTED", remove quotes
		val = strings.Trim(val, "\"")

		switch key {
		case "mdState":
			status.State = val // STARTED, STOPPED, etc.
		case "mdResync":
			fmt.Sscanf(val, "%d", &status.ParityTotal)
		case "mdResyncPos":
			fmt.Sscanf(val, "%d", &status.ParityPos)
		case "mdCheck":
			// CORRECT, NOCORRECT
		}
	}

	// Refine Parity Check parsing
	if status.ParityTotal > 0 && status.ParityPos > 0 && status.ParityPos < status.ParityTotal {
		status.ParityCheckRunning = true
		status.ParityStatus = "RUNNING"
	} else {
		status.ParityCheckRunning = false
		status.ParityStatus = "COMPLETED" // Or NEVER_RUN, simplified
	}

	return status, nil
}

func handleVmInfo(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := r.Header.Get("x-api-key")
	if !isValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vmName := r.URL.Query().Get("vm")
	if vmName == "" {
		http.Error(w, "Missing vm param", http.StatusBadRequest)
		return
	}

	info, err := getVmInfo(vmName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleVmAutostart(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := r.Header.Get("x-api-key")
	if !isValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AutostartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Vm == "" {
		http.Error(w, "Missing vm name", http.StatusBadRequest)
		return
	}

	if err := setVmAutostart(req.Vm, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 1. Security Check: Validate x-api-key
	// Check Sec-WebSocket-Protocol (standard way to pass auth in WS from browser)
	protocolKey := r.Header.Get("Sec-WebSocket-Protocol")

	clientKey := ""
	if isValidKey(protocolKey) {
		clientKey = protocolKey
	} else {
		clientKey = r.Header.Get("x-api-key")
	}

	// Fallback 2: Check 'token' query parameter (for standard NoVNC path connection)
	if clientKey == "" {
		clientKey = r.URL.Query().Get("token")
	}

	if !isValidKey(clientKey) {
		log.Printf("Unauthorized WS access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade
	responseHeader := http.Header{}
	if protocolKey != "" {
		responseHeader.Add("Sec-WebSocket-Protocol", protocolKey)
	}

	conn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer conn.Close()

	termType := r.URL.Query().Get("type")
	if termType == "" {
		termType = "docker" // Default
	}

	// -------------------------------------------------------------
	// VM VNC PROXY
	// -------------------------------------------------------------
	if termType == "vm-vnc" {
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}

		port, err := getVncPort(vmName)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("Error finding VNC port: "+err.Error()))
			return
		}

		// Connect to VNC server on localhost
		vncConn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("Error connecting to VNC: "+err.Error()))
			return
		}
		defer vncConn.Close()

		// Proxy WebSocket <-> TCP
		errChan := make(chan error, 2)

		// WS -> TCP
		go func() {
			for {
				_, msg, err := conn.ReadMessage()
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
					if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
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
		return
	}

	// -------------------------------------------------------------
	// ALL OTHER TYPES (PTY BASED)
	// -------------------------------------------------------------

	var cmd *exec.Cmd

	switch termType {
	case "host":
		cmd = exec.Command("/bin/bash")
		cmd.Env = append(os.Environ(), "TERM=xterm")

	case "docker":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		cmd = exec.Command("docker", "exec", "-it", containerID, "sh")

	case "vm": // Serial Console
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		cmd = exec.Command("virsh", "console", vmName)

	case "vm-log": // VM Logs
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		// Location for logs in Unraid/Libvirt
		logPath := fmt.Sprintf("/var/log/libvirt/qemu/%s.log", vmName)
		cmd = exec.Command("tail", "-f", "-n", "100", logPath)

	case "docker-log":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		cmd = exec.Command("docker", "logs", "-f", "--tail", "100", containerID)

	case "array-status":
		// Loop and send updates
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		var lastStatus ArrayStatus
		for range ticker.C {
			status, err := getArrayStatus()
			if err != nil {
				// Log but don't crash
				log.Println("Error getting array status:", err)
				continue
			}

			if *status == lastStatus {
				continue
			}
			lastStatus = *status

			// Calculate Progress
			var progress float64 = 0
			if status.ParityTotal > 0 {
				progress = (float64(status.ParityPos) / float64(status.ParityTotal)) * 100
				if progress > 100 {
					progress = 100
				}
			}

			// Wrap match UnraidClient expectation
			wrapper := map[string]interface{}{
				"array": map[string]interface{}{
					"state": status.State,
					"parityCheckStatus": map[string]interface{}{
						"status":     status.ParityStatus,
						"progress":   progress,
						"running":    status.ParityCheckRunning,
						"errors":     0, // TODO: Parse mdNumErrors if needed
						"speed":      "0",
						"duration":   0,
						"date":       "0",
						"correcting": false,
						"paused":     false,
					},
				},
			}

			if err := conn.WriteJSON(wrapper); err != nil {
				return
			}
		}

	case "docker-stats":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Run docker stats --no-stream --format '{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}' <id>
			// We use a custom separator "|" to parse easily
			out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}", containerID).Output()
			if err != nil {
				// Container might be stopped or invalid, just skip iteration
				continue
			}

			// Parse output: "0.00%|0.00%|10MiB / 1GiB"
			parts := strings.Split(strings.TrimSpace(string(out)), "|")
			if len(parts) >= 3 {
				stats := map[string]string{
					"CPUPerc":  parts[0],
					"MemPerc":  parts[1],
					"MemUsage": parts[2],
				}

				if err := conn.WriteJSON(stats); err != nil {
					return
				}
			}
		}

	default:
		conn.WriteMessage(websocket.TextMessage, []byte("Error: invalid type"))
		return
	}

	// PTY Execution
	ptmx, err := pty.Start(cmd)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("Error starting pty: "+err.Error()))
		return
	}
	defer func() { _ = ptmx.Close() }()

	// WS -> PTY
	go func() {
		for {
			_, message, err := conn.ReadMessage()
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
			if err != io.EOF {
				// Log?
			}
			break
		}
		err = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
		if err != nil {
			break
		}
	}
}

func main() {
	port := flag.String("port", "9876", "Port to listen on")
	host := flag.String("host", "0.0.0.0", "Host to bind to")
	flag.Parse()

	addr := *host + ":" + *port

	// Fix MIME types: restricted environments (like minimal Linux or iOS WebViews)
	// often reject stylesheets if Content-Type is not text/css.
	// Go's mime package relies on OS files which might be missing on Unraid.
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".mjs", "application/javascript")
	mime.AddExtensionType(".html", "text/html")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".wasm", "application/wasm")

	// Initial load
	loadApiKeys()

	// Periodically reload keys
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			loadApiKeys()
		}
	}()

	// Serve Index with Key Injection
	http.HandleFunc("/", handleIndex)

	// Full NoVNC Static Files
	// We serve everything under web/novnc at /novnc/
	// Use fs.Sub to root the file server at web/novnc
	novncFS, err := fs.Sub(content, "web/novnc")
	if err != nil {
		log.Fatal("Failed to create sub-fs for novnc:", err)
	}

	// Wrap FileServer with CORS to allow WebView access without issues
	outputFS := http.FileServer(http.FS(novncFS))
	strippedHandler := http.StripPrefix("/novnc/", outputFS)

	http.Handle("/novnc/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			return
		}
		strippedHandler.ServeHTTP(w, r)
	}))

	http.HandleFunc("/api/vm/info", handleVmInfo)
	http.HandleFunc("/api/vm/autostart", handleVmAutostart)
	http.HandleFunc("/api/docker/action", handleContainerAction)
	http.HandleFunc("/connect", handleWebSocket)

	fmt.Printf("Raidman Terminal Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

type ContainerActionRequest struct {
	Container string `json:"container"`
	Action    string `json:"action"` // pause, unpause
}

func handleContainerAction(w http.ResponseWriter, r *http.Request) {
	// Auth
	clientKey := r.Header.Get("x-api-key")
	if !isValidKey(clientKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ContainerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Container == "" || (req.Action != "pause" && req.Action != "unpause") {
		http.Error(w, "Invalid params", http.StatusBadRequest)
		return
	}

	// Execute Docker command
	if err := exec.Command("docker", req.Action, req.Container).Run(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
