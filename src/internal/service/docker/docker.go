package docker

import (
	"encoding/json"
	"fmt"
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
	allowed := map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"kill":    true,
		"pause":   true,
		"unpause": true,
	}
	if !allowed[action] {
		return nil // Invalid action, maybe return error?
	}
	out, err := exec.Command("docker", action, container).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker action failed: %v, output: %s", err, string(out))
	}
	return nil
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

func GetContainers() ([]interface{}, error) {
	// 1. Get List of All Container IDs
	// docker ps -a -q
	cmdIds := exec.Command("docker", "ps", "-a", "-q")
	outIds, err := cmdIds.Output()
	if err != nil {
		return nil, err
	}

	ids := strings.Fields(strings.TrimSpace(string(outIds)))
	if len(ids) == 0 {
		return []interface{}{}, nil
	}

	// 2. Inspect All Containers
	// docker inspect [id1] [id2] ...
	args := append([]string{"inspect"}, ids...)
	cmdInspect := exec.Command("docker", args...)
	outInspect, err := cmdInspect.Output()
	if err != nil {
		return nil, err
	}

	// 3. Unmarshal into generic slice
	var containers []interface{}
	if err := json.Unmarshal(outInspect, &containers); err != nil {
		return nil, err
	}

	return containers, nil
}
