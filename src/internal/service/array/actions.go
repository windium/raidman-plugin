package array

import (
	"fmt"
	"os/exec"
)

// ExecuteAction performs array-wide operations like spinup/spindown
func ExecuteAction(action string) error {
	var cmd *exec.Cmd

	switch action {
	case "spinup":
		// 'mdcmd spinup' spins up all disks
		cmd = exec.Command("mdcmd", "spinup")
	case "spindown":
		// 'mdcmd spindown' spins down all disks
		cmd = exec.Command("mdcmd", "spindown")
	default:
		return fmt.Errorf("unknown array action: %s", action)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute %s: %s (out: %s)", action, err, string(output))
	}

	return nil
}
