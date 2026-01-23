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

type Container struct {
	ID      string `json:"id"`
	Names   string `json:"names"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Ports   string `json:"ports"`
	Created string `json:"created"`
}

func GetContainers() ([]Container, error) {
	// docker ps -a --format "{{json .}}"
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var containers []Container
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Docker raw JSON struct
		var raw struct {
			ID        string `json:"ID"`
			Names     string `json:"Names"`
			Image     string `json:"Image"`
			State     string `json:"State"`
			Status    string `json:"Status"`
			Ports     string `json:"Ports"`
			CreatedAt string `json:"CreatedAt"`
		}

		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		containers = append(containers, Container{
			ID:      raw.ID,
			Names:   raw.Names,
			Image:   raw.Image,
			State:   raw.State,
			Status:  raw.Status,
			Ports:   raw.Ports,
			Created: raw.CreatedAt,
		})
	}

	return containers, nil
}
