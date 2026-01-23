package system

import (
	"fmt"
	"os/exec"
)

// ExecuteAction runs a system command based on the action provided.
// Supported actions: "shutdown", "reboot"
func ExecuteAction(action string) error {
	var cmd *exec.Cmd

	switch action {
	case "shutdown":
		// powerdown is the standard Unraid graceful shutdown script
		cmd = exec.Command("powerdown")
	case "reboot":
		// reboot is standard
		cmd = exec.Command("reboot")
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %v", action, err)
	}

	// We don't wait for it to finish as these commands might kill the plugin process immediately
	// or take a while. Start() is enough to trigger it.

	return nil
}
