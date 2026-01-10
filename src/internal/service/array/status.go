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
		return &domain.ArrayStatus{
			State:              "STARTED",
			ParityStatus:       "NEVER_RUN",
			ParityCheckRunning: false,
			Disks: []domain.ArrayDisk{
				{Id: "0", Name: "parity", Device: "sdb", State: "DISK_OK", Size: 1000000000, NumReads: 123, NumWrites: 456},
				{Id: "1", Name: "disk1", Device: "sdc", State: "DISK_OK", Size: 1000000000, NumReads: 789, NumWrites: 101},
			},
			Caches: []domain.ArrayDisk{
				{Id: "cache", Name: "cache", Device: "nvme0n1", State: "DISK_OK", Size: 500000000, NumReads: 999, NumWrites: 888},
			},
		}, nil
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	status := &domain.ArrayStatus{
		State:        "UNKNOWN",
		ParityStatus: "NEVER_RUN",
		Disks:        []domain.ArrayDisk{},
		Caches:       []domain.ArrayDisk{},
	}

	diskMap := make(map[string]*domain.ArrayDisk)

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

		// General Status
		switch key {
		case "mdState":
			status.State = val // STARTED, STOPPED, etc.
		case "mdResync":
			fmt.Sscanf(val, "%d", &status.ParityTotal)
		case "mdResyncPos":
			fmt.Sscanf(val, "%d", &status.ParityPos)
		}

		// Disk Parsing logic
		// Format: diskName.0=parity, diskName.cache=...
		if strings.Contains(key, ".") {
			keyParts := strings.Split(key, ".")
			// support multipart keys if needed, but usually just name.id
			if len(keyParts) >= 2 {
				field := keyParts[0]
				idStr := keyParts[1]

				if _, ok := diskMap[idStr]; !ok {
					diskMap[idStr] = &domain.ArrayDisk{Id: idStr}
				}
				d := diskMap[idStr]

				switch field {
				case "diskName":
					d.Name = val
				case "rdevName":
					d.Device = val
				case "diskSize":
					fmt.Sscanf(val, "%d", &d.Size)
				case "diskState":
					d.State = val
				case "rdevNumReads": // Try rdev first
					fmt.Sscanf(val, "%d", &d.NumReads)
				case "rdevNumWrites":
					fmt.Sscanf(val, "%d", &d.NumWrites)
				case "rdevNumErrors":
					fmt.Sscanf(val, "%d", &d.NumErrors)
				// Fallback/Legacy keys
				case "diskRead":
					if d.NumReads == 0 {
						fmt.Sscanf(val, "%d", &d.NumReads)
					}
				case "diskWrite":
					if d.NumWrites == 0 {
						fmt.Sscanf(val, "%d", &d.NumWrites)
					}
				}
			}
		}
	}

	// Track deployed devices to prevent duplicates in Caches/Pools
	assignedDevices := make(map[string]bool)

	// 1. Identify all Array Disks (Numeric) first
	for id, d := range diskMap {
		if d.Name == "" {
			continue
		}

		var numericId int
		if _, err := fmt.Sscanf(id, "%d", &numericId); err == nil {
			d.Idx = numericId
			status.Disks = append(status.Disks, *d)
			if d.Device != "" {
				assignedDevices[d.Device] = true
			}
		}
	}

	// 2. Identify Pools (Non-numeric), excluding assigned devices
	for id, d := range diskMap {
		if d.Name == "" {
			continue
		}

		var numericId int
		if _, err := fmt.Sscanf(id, "%d", &numericId); err != nil {
			// Non-numeric
			// Check if device is already assigned to Array
			if _, exists := assignedDevices[d.Device]; exists {
				continue
			}
			// Also filter out partition-like names if they are orphans (e.g. md1p1)
			if strings.HasPrefix(d.Name, "md") {
				continue
			}
			status.Caches = append(status.Caches, *d)
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
