package array

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"raidman/src/internal/domain"
)

func GetArrayStatus() (*domain.ArrayStatus, error) {
	// 1. Run mdcmd status
	// Check if mdcmd exists
	cmd := exec.Command("/usr/local/sbin/mdcmd", "status")
	if _, err := os.Stat("/usr/local/sbin/mdcmd"); os.IsNotExist(err) {
		// Fallback for dev/testing if not on Unraid
		return &domain.ArrayStatus{State: "STARTED", ParityStatus: "NEVER_RUN", ParityCheckRunning: false}, nil
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	status := &domain.ArrayStatus{
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
