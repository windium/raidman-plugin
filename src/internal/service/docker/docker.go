package docker

import (
	"os/exec"
)

func ExecuteContainerAction(container string, action string) error {
	// Validate action to prevent command injection
	if action != "pause" && action != "unpause" {
		return nil // Or error? Legacy code returned 500 on execution error, but validated before.
	}
	return exec.Command("docker", action, container).Run()
}
