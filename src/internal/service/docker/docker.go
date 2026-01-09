package docker

import (
	"os/exec"
	"strings"
)

type ContainerStats struct {
	ID       string `json:"ID"`
	CPUPerc  string `json:"CPUPerc"`
	MemPerc  string `json:"MemPerc"`
	MemUsage string `json:"MemUsage"`
}

func ExecuteContainerAction(container string, action string) error {
	// Validate action to prevent command injection
	if action != "pause" && action != "unpause" {
		return nil // Or error? Legacy code returned 500 on execution error, but validated before.
	}
	return exec.Command("docker", action, container).Run()
}

func GetContainerStats(containerID string) ([]ContainerStats, error) {
	// Run docker stats --no-stream --format '{{.ID}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}' [containerID]
	args := []string{"stats", "--no-stream", "--format", "{{.ID}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}"}
	if containerID != "" {
		args = append(args, containerID)
	}

	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, err
	}

	var results []ContainerStats
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			stats := ContainerStats{
				ID:       parts[0],
				CPUPerc:  parts[1],
				MemPerc:  parts[2],
				MemUsage: parts[3],
			}
			results = append(results, stats)
		}
	}
	return results, nil
}
