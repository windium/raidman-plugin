package system

import (
	"fmt"
	"os/exec"
)

// ExecuteAction runs a system command based on the action provided.

func ExecuteAction(action string) error {
	var cmd *exec.Cmd

	switch action {
	case "shutdown":

		cmd = exec.Command("powerdown")
	case "reboot":

		cmd = exec.Command("reboot")
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %v", action, err)
	}

	return nil
}
