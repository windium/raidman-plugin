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
			State: "STARTED",
			ParityCheckStatus: &domain.ParityCheckStatus{
				Status:   "IDLE",
				Running:  false,
				Progress: "100.0",
				Date:     "1680000000",
				Duration: 3600,
				Speed:    "150.5 MB/s",
				Errors:   0,
			},
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
		State: "UNKNOWN",
		ParityCheckStatus: &domain.ParityCheckStatus{
			Status: "IDLE",
			Speed:  "0",
			Date:   "0",
		},
		Parities: []domain.ArrayDisk{},
		Disks:    []domain.ArrayDisk{},
		Caches:   []domain.ArrayDisk{},
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
			fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Total)
		case "mdResyncPos":
			fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Pos)
		case "mdResyncCorr":
			fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Errors)
		case "sbSynced":
			// Last check date timestamp
			status.ParityCheckStatus.Date = val
		case "mdResyncDt":
			fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Duration)
		case "mdResyncSp":
			status.ParityCheckStatus.Speed = val
		}

		// Calculate Status/Running
		if status.ParityCheckStatus.Total > 0 && status.ParityCheckStatus.Pos > 0 && status.ParityCheckStatus.Pos < status.ParityCheckStatus.Total {
			status.ParityCheckStatus.Running = true
			status.ParityCheckStatus.Status = "RUNNING" // Or PAUSED if mdState says so
			// Calculate progress
			pct := float64(status.ParityCheckStatus.Pos) / float64(status.ParityCheckStatus.Total) * 100.0
			status.ParityCheckStatus.Progress = fmt.Sprintf("%.1f", pct)
		} else {
			status.ParityCheckStatus.Running = false
			status.ParityCheckStatus.Status = "IDLE"
			status.ParityCheckStatus.Progress = "100.0"
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
				case "rdevNumReads":
					var valInt int64
					fmt.Sscanf(val, "%d", &valInt)
					if valInt > d.NumReads {
						d.NumReads = valInt
					}
				case "rdevNumWrites":
					var valInt int64
					fmt.Sscanf(val, "%d", &valInt)
					if valInt > d.NumWrites {
						d.NumWrites = valInt
					}
				case "rdevNumErrors":
					fmt.Sscanf(val, "%d", &d.NumErrors)
				// Primary counters
				case "diskRead":
					var valInt int64
					fmt.Sscanf(val, "%d", &valInt)
					if valInt > d.NumReads {
						d.NumReads = valInt
					}
				case "diskWrite":
					var valInt int64
					fmt.Sscanf(val, "%d", &valInt)
					if valInt > d.NumWrites {
						d.NumWrites = valInt
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

	return status, nil
}
