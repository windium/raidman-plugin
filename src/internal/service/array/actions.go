package array

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecuteAction performs array-wide operations like spinup/spindown
func ExecuteAction(action string) error {

	matches, err := filepath.Glob("/dev/md*")
	if err != nil {
		return fmt.Errorf("failed to list array devices: %v", err)
	}

	switch action {
	case "spinup", "spindown", "check", "nocheck", "sync", "nosync":

	default:
		return fmt.Errorf("invalid action: %s", action)
	}

	if len(matches) == 0 {
		return nil // No array disks to manage
	}

	var errors []string

	for _, devicePath := range matches {

		id := strings.TrimPrefix(devicePath, "/dev/md")
		if id == "" || id == devicePath {
			continue
		}

		if strings.Contains(id, "p") {
			continue
		}

		isNumeric := true
		for _, c := range id {
			if c < '0' || c > '9' {
				isNumeric = false
				break
			}
		}
		if !isNumeric {
			continue
		}

		// Execute serially to avoid contention on /proc/mdcmd
		cmd := exec.Command("mdcmd", action, id)
		if output, err := cmd.CombinedOutput(); err != nil {

			errors = append(errors, fmt.Sprintf("disk %s: %v (out: %s)", id, err, string(output)))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during %s: %s", action, strings.Join(errors, "; "))
	}

	return nil
}
