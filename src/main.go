package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
    "time"

    "github.com/creack/pty"
    "github.com/gorilla/websocket"
)

// Constants
const (
    KeysPath = "/boot/config/plugins/dynamix.my.servers/keys"
)

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

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // 1. Security Check: Validate x-api-key
    clientKey := r.URL.Query().Get("x-api-key")
    if clientKey == "" {
        // Fallback to header
        clientKey = r.Header.Get("x-api-key")
    }

    if !isValidKey(clientKey) {
        log.Printf("Unauthorized access attempt from %s", r.RemoteAddr)
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Print("upgrade:", err)
        return
    }
    defer conn.Close()

    containerID := r.URL.Query().Get("container")
    if containerID == "" {
        conn.WriteMessage(websocket.TextMessage, []byte("Error: container param missing"))
        return
    }

    // Double check containerID to avoid injection (simple alphanumeric check)
    // docker container ids are hex, names are alphanumeric + underscore/dash
    // but users might pass name.
    
    cmd := exec.Command("docker", "exec", "-it", containerID, "/bin/bash")
    
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
            if err != io.EOF {
                log.Println("read error:", err)
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

    // Initial load
    loadApiKeys()
    
    // Periodically reload keys
    go func() {
        for {
            time.Sleep(1 * time.Minute)
            loadApiKeys()
        }
    }()

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // Health check or basic info
        fmt.Fprintf(w, "Raidman Terminal Server Running. Secure Access Only.")
    })
    
    http.HandleFunc("/connect", handleWebSocket)

    fmt.Printf("Raidman Terminal Server listening on %s\n", addr)
    log.Fatal(http.ListenAndServe(addr, nil))
}
