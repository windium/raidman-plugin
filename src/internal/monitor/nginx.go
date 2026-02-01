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
)

type NginxMonitor struct {
	watcher *fsnotify.Watcher
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
	path := filepath.Join(NginxConfDir, LocationsConfFile)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	contentBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Monitor: Error reading %s: %v", path, err)
		return
	}
	content := string(contentBytes)

	if !strings.Contains(content, RaidmanConfLine) {
		log.Printf("Monitor: Raidman config missing in %s, re-injecting...", LocationsConfFile)

		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Monitor: Error opening %s: %v", path, err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString("\n" + RaidmanConfLine + "\n"); err != nil {
			log.Printf("Monitor: Error appending config: %v", err)
			return
		}

		// Reload Nginx
		cmd := exec.Command("/usr/sbin/nginx", "-s", "reload")
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Monitor: Error reloading Nginx: %v, Output: %s", err, string(output))
		} else {
			log.Println("Monitor: Nginx reloaded successfully.")
		}
	}
}
