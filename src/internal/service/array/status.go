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
		Parities:     []domain.ArrayDisk{},
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

	// Flatten map to slices
	for id, d := range diskMap {
		if d.Name == "" {
			continue
		}

		// Heuristic to separate Array Disks from Cache/Pools
		// Array disks usually have numeric IDs (0, 1, 2...)
		// Cache/Pools usually have string IDs (cache, poolname...)
		var numericId int
		_, err := fmt.Sscanf(id, "%d", &numericId)
		isNumeric := err == nil

		if isNumeric {
			d.Idx = numericId
			status.Disks = append(status.Disks, *d)
		} else if strings.HasPrefix(d.Name, "parity") {
			status.Parities = append(status.Parities, *d)
		} else {
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
