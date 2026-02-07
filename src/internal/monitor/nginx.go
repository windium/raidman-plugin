package monitor

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	NginxConfDir      = "/etc/nginx/conf.d"
	LocationsConfFile = "locations.conf"
	RaidmanConfLine   = "include /etc/nginx/conf.d/raidman.conf;"
	NginxBinary       = "/usr/sbin/nginx"
)

type NginxMonitor struct {
	watcher     *fsnotify.Watcher
	lastFailure time.Time
}

func NewNginxMonitor() (*NginxMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &NginxMonitor{watcher: watcher}, nil
}

func (m *NginxMonitor) Start() {

	if err := m.watcher.Add(NginxConfDir); err != nil {
		log.Printf("Monitor: Error watching %s: %v. Monitoring disabled.", NginxConfDir, err)
		return
	}

	log.Printf("Monitor: Started watching %s for %s", NginxConfDir, LocationsConfFile)

	// Initial check on startup
	m.checkAndInject()

	go func() {
		defer m.watcher.Close()
		for {
			select {
			case event, ok := <-m.watcher.Events:
				if !ok {
					return
				}

				if filepath.Base(event.Name) == LocationsConfFile {
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Chmod == fsnotify.Chmod {
						// Small debounce to avoid race conditions with atomic writes
						time.Sleep(100 * time.Millisecond)
						m.checkAndInject()
					}
				}
			case err, ok := <-m.watcher.Errors:
				if !ok {
					return
				}
				log.Println("Monitor: Watcher error:", err)
			}
		}
	}()
}

func (m *NginxMonitor) checkAndInject() {
	// Cooldown check: if we failed recently, don't try again immediately to avoid loops
	if time.Since(m.lastFailure) < 30*time.Second {
		return
	}

	path := filepath.Join(NginxConfDir, LocationsConfFile)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	// 1. Check if Nginx is currently healthy before we touch anything
	if err := validateNginxConfig(); err != nil {
		log.Printf("Monitor: Pre-check failed. Nginx config is currently invalid: %v. Skipping injection.", err)
		return
	}

	contentBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Monitor: Error reading %s: %v", path, err)
		return
	}
	content := string(contentBytes)

	if !strings.Contains(content, RaidmanConfLine) {
		log.Printf("Monitor: Raidman config missing in %s, attempting injection...", LocationsConfFile)

		// 2. Inject config
		newContent := content + "\n" + RaidmanConfLine + "\n"
		if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
			log.Printf("Monitor: Error writing config: %v", err)
			return
		}

		// 3. Post-validation
		if err := validateNginxConfig(); err != nil {
			log.Printf("Monitor: Injection resulted in invalid config: %v. Reverting...", err)

			// 4. Rollback
			if err := os.WriteFile(path, contentBytes, 0644); err != nil {
				log.Printf("Monitor: CRITICAL ERROR: Failed to revert config: %v", err)
			} else {
				log.Println("Monitor: Reverted config successfully.")
			}

			m.lastFailure = time.Now()

			// Try to reload to ensure we are back to a good state (if possible)
			reloadNginx()
			return
		}

		// 5. Success - Reload
		if err := reloadNginx(); err != nil {
			log.Printf("Monitor: Config valid but reload failed: %v", err)
		} else {
			log.Println("Monitor: Nginx reloaded successfully with Raidman config.")
		}
	}
}

func validateNginxConfig() error {
	cmd := exec.Command(NginxBinary, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Monitor: Nginx config check failed: %v, Output: %s", err, string(output))
		return err
	}
	return nil
}

func reloadNginx() error {
	// Check if Nginx PID exists
	if _, err := os.Stat("/var/run/nginx.pid"); os.IsNotExist(err) {
		log.Println("Monitor: Nginx PID file not found. Skipping reload.")
		return nil
	}

	cmd := exec.Command(NginxBinary, "-s", "reload")
	return cmd.Run()
}
