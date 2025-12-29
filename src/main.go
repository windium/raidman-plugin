package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 1. Security Check: Validate x-api-key
	// Check Sec-WebSocket-Protocol (standard way to pass auth in WS from browser)
	protocolKey := r.Header.Get("Sec-WebSocket-Protocol")

	// Some clients might send it as "x-api-key, other-protocol" or just the key
	// We assume the key IS the protocol or part of it.
	// Simple validation: is the protocol a valid key?
	clientKey := ""
	if isValidKey(protocolKey) {
		clientKey = protocolKey
	} else {
		// Fallback: Check standard header just in case client supports it
		clientKey = r.Header.Get("x-api-key")
	}

	if !isValidKey(clientKey) {
		log.Printf("Unauthorized WS access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade
	// We MUST echo back the protocol to satisfy the client if it sent one
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

	var cmd *exec.Cmd

	switch termType {
	case "host":
		// Host Terminal
		cmd = exec.Command("/bin/bash")
		// Set basic environment variables for terminal
		cmd.Env = append(os.Environ(), "TERM=xterm")

	case "docker":
		containerID := r.URL.Query().Get("container")
		if containerID == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
			return
		}
		// Docker Exec
		cmd = exec.Command("docker", "exec", "-it", containerID, "sh")

	case "vm":
		vmName := r.URL.Query().Get("vm")
		if vmName == "" {
			conn.WriteMessage(websocket.TextMessage, []byte("Error: vm param missing"))
			return
		}
		// Virsh Console
		// Requires 'virsh' binary and VM configured with serial console
		cmd = exec.Command("virsh", "console", vmName)

	default:
		conn.WriteMessage(websocket.TextMessage, []byte("Error: invalid type"))
		return
	}

	// Start the command with a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("Error starting pty: "+err.Error()))
		return
	}
	defer func() { _ = ptmx.Close() }()

	// Copy stdin to the pty
	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			ptmx.Write(message)
		}
	}()

	// Copy pty stdout to the websocket
	buf := make([]byte, 1024)
	for {
		n, err := ptmx.Read(buf)
		if err != nil {
			// io.EOF means command exited
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

	http.HandleFunc("/connect", handleWebSocket)

	fmt.Printf("Raidman Terminal Server listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
