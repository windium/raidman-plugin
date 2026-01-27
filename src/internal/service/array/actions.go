package array

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecuteAction performs array-wide operations like spinup/spindown
func ExecuteAction(action string) error {
	// mdcmd requires a disk ID for spinup/spindown.
	// We must iterate over all array devices (/dev/md*).

	// Find all array devices
	matches, err := filepath.Glob("/dev/md*")
	if err != nil {
		return fmt.Errorf("failed to list array devices: %v", err)
	}

	if len(matches) == 0 {
		return nil // No array disks to manage
	}

	var errors []string

	for _, devicePath := range matches {
		// Device path is like /dev/md1, /dev/md0
		// We need the number.
		// Actually mdcmd typically takes the number (e.g. '1', '0')
		// Or can we pass the device? Usually mdcmd usage is `mdcmd spinup 1`.

		id := strings.TrimPrefix(devicePath, "/dev/md")
		if id == "" || id == devicePath {
			continue // Should not happen with glob /dev/md* unless /dev/md exists?
		}

		// Skip if ID is not numeric? /dev/md* usually matches md0, md1...
		// But just in case

		// Execute serially to avoid contention on /proc/mdcmd
		cmd := exec.Command("mdcmd", action, id)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Save error but continue trying others
			errors = append(errors, fmt.Sprintf("disk %s: %v (out: %s)", id, err, string(output)))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered errors during %s: %s", action, strings.Join(errors, "; "))
	}

	return nil
}
