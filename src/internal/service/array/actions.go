package array

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecuteAction performs array-wide operations like spinup/spindown
func ExecuteAction(action string) error {

	// 1. Handle Global Commands (check, nocheck, sync, nosync)
	// These commands are executed ONCE, not per disk.
	switch action {
	case "check", "nocheck", "sync", "nosync":
		cmd := exec.Command("mdcmd", action)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to execute global action %s: %v (out: %s)", action, err, string(output))
		}
		return nil

	case "spinup", "spindown":
		// These are per-disk (or we simulate global spinup/down by iterating)
		// Fallthrough to per-disk logic below

	default:
		return fmt.Errorf("invalid action: %s", action)
	}

	// 2. Handle Per-Disk Commands (spinup, spindown)
	matches, err := filepath.Glob("/dev/md*")
	if err != nil {
		return fmt.Errorf("failed to list array devices: %v", err)
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
			// Specific error handling or just log?
			// For spinup/down, some disks might fail but we want to try all.
			errors = append(errors, fmt.Sprintf("disk %s: %v (out: %s)", id, err, string(output)))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during %s: %s", action, strings.Join(errors, "; "))
	}

	return nil
}
