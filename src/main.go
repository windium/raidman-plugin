package main

import (
	"embed"
	"encoding/json"
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

func getVncPort(vmName string) (string, error) {
	// virsh domdisplay returns something like ":0" (for 5900) or "vnc://127.0.0.1:0"
	out, err := exec.Command("virsh", "domdisplay", vmName).Output()
	if err != nil {
		return "", err
	}
	output := strings.TrimSpace(string(out))

	// Handle ":0" format
	if strings.HasPrefix(output, ":") {
		display := output[1:]
		// Port is 5900 + display
		var d int
		_, err := fmt.Sscan(display, &d)
		if err != nil {
			return "", fmt.Errorf("invalid display: %s", display)
		}
		return fmt.Sprintf("%d", 5900+d), nil
	}

	// Handle "vnc://..." format if necessary, though simpler parsing might suffice for now
	// Unraid usually returns :0, :1 etc.
	return "", fmt.Errorf("unknown display format: %s", output)
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

	http.HandleFunc("/connect", handleWebSocket)

	fmt.Printf("Raidman Terminal Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
