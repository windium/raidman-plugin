package array

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"raidman/src/internal/domain"
)

func GetArrayStatus() (*domain.ArrayStatus, error) {
	// 1. Read /var/local/emhttp/var.ini for Global Status
	varIniPath := "/var/local/emhttp/var.ini"
	if _, err := os.Stat(varIniPath); os.IsNotExist(err) {
		// Fallback for dev/testing
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
				{Id: "1", Name: "disk1", Device: "sdc", State: "DISK_OK", Size: 1000000000, NumReads: 789, NumWrites: 101, Idx: 1},
			},
			Parities: []domain.ArrayDisk{
				{Id: "0", Name: "parity", Device: "sdb", State: "DISK_OK", Size: 1000000000, NumReads: 123, NumWrites: 456, Idx: 0},
			},
			Caches: []domain.ArrayDisk{
				{Id: "cache", Name: "cache", Device: "nvme0n1", State: "DISK_OK", Size: 500000000, NumReads: 999, NumWrites: 888},
			},
			Boot: &domain.ArrayDisk{
				Id: "flash", Name: "flash", Device: "sdd", State: "DISK_OK", Size: 16000000, NumReads: 10, NumWrites: 20,
			},
		}, nil
	}

	status := &domain.ArrayStatus{
		State: "UNKNOWN",
		ParityCheckStatus: &domain.ParityCheckStatus{
			Status: "IDLE",
		},
		Parities:   []domain.ArrayDisk{},
		Disks:      []domain.ArrayDisk{},
		Caches:     []domain.ArrayDisk{},
		Unassigned: []domain.ArrayDisk{},
		Boot:       nil,
	}

	varMap, err := parseIniFile(varIniPath)
	if err == nil {
		if val, ok := varMap["mdState"]; ok {
			status.State = val
		}

		// Parity Check Details
		var total, pos, errs, dur int64
		fmt.Sscanf(varMap["mdResync"], "%d", &total)
		fmt.Sscanf(varMap["mdResyncPos"], "%d", &pos)
		fmt.Sscanf(varMap["mdResyncCorr"], "%d", &errs)
		fmt.Sscanf(varMap["mdResyncDt"], "%d", &dur)

		status.ParityCheckStatus.Total = total
		status.ParityCheckStatus.Pos = pos
		status.ParityCheckStatus.Errors = errs
		status.ParityCheckStatus.Duration = dur
		status.ParityCheckStatus.Date = varMap["sbSynced"] // Last check timestamp
		status.ParityCheckStatus.Speed = varMap["mdResyncSp"]

		if total > 0 && pos > 0 && pos < total {
			status.ParityCheckStatus.Running = true
			status.ParityCheckStatus.Status = "RUNNING"
			if status.State != "STARTED" {
				status.ParityCheckStatus.Status = "PAUSED" // Rough guess
			}
			pct := float64(pos) / float64(total) * 100.0
			status.ParityCheckStatus.Progress = fmt.Sprintf("%.1f", pct)
		} else {
			status.ParityCheckStatus.Running = false
			status.ParityCheckStatus.Status = "IDLE"
			status.ParityCheckStatus.Progress = "100.0"
		}
	}

	// Helper to extract stats with fallback keys
	parseStats := func(data map[string]string) (int64, int64, int64, int64, int64) {
		var r, w, e, rb, wb int64
		// Reads
		if v, ok := data["numReads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		} else if v, ok := data["rdevNumReads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		} else if v, ok := data["reads"]; ok {
			fmt.Sscanf(v, "%d", &r)
		}
		// Writes
		if v, ok := data["numWrites"]; ok {
			fmt.Sscanf(v, "%d", &w)
		} else if v, ok := data["rdevNumWrites"]; ok {
			fmt.Sscanf(v, "%d", &w)
		} else if v, ok := data["writes"]; ok {
			fmt.Sscanf(v, "%d", &w)
		}
		// Errors
		if v, ok := data["numErrors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		} else if v, ok := data["rdevNumErrors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		} else if v, ok := data["errors"]; ok {
			fmt.Sscanf(v, "%d", &e)
		}

		// Bytes (Sectors * 512)
		// Check for rsect/wsect (mdcmd standard) or read_bytes fallback
		var rs, ws int64
		if v, ok := data["rsect"]; ok {
			fmt.Sscanf(v, "%d", &rs)
			rb = rs * 512
		} else if v, ok := data["read_bytes"]; ok {
			// Some versions might have bytes directly?
			fmt.Sscanf(v, "%d", &rb)
		}
		if v, ok := data["wsect"]; ok {
			fmt.Sscanf(v, "%d", &ws)
			wb = ws * 512
		} else if v, ok := data["write_bytes"]; ok {
			fmt.Sscanf(v, "%d", &wb)
		}

		return r, w, e, rb, wb
	}

	// 2. Read /var/local/emhttp/disks.ini for Disk Details
	disksIniPath := "/var/local/emhttp/disks.ini"
	disksMap, err := parseIniSections(disksIniPath)
	if err == nil {
		for section, data := range disksMap {
			if len(data) == 0 {
				continue
			}

			d := domain.ArrayDisk{
				Id:         section,
				Name:       data["name"],
				Identifier: data["id"],
				Device:     data["device"],
				State:      data["status"],
			}
			fmt.Sscanf(data["size"], "%d", &d.Size)
			fmt.Sscanf(data["idx"], "%d", &d.Idx)

			// Use robust parsing
			d.NumReads, d.NumWrites, d.NumErrors, d.ReadBytes, d.WriteBytes = parseStats(data)

			// Temp can be "*" or number
			tempVal := data["temp"]
			if tempVal != "*" && tempVal != "" {
				fmt.Sscanf(tempVal, "%d", &d.Temp)
			}

			diskType := data["type"]

			switch diskType {
			case "Flash":
				status.Boot = &d
			case "Parity":
				status.Parities = append(status.Parities, d)
			case "Data":
				status.Disks = append(status.Disks, d)
			case "Cache":
				status.Caches = append(status.Caches, d)
			default:
				if d.Name != "" {
					status.Caches = append(status.Caches, d)
				}
			}
		}
	}

	// 3. Read /var/local/emhttp/devs.ini for Unassigned Devices
	devsIniPath := "/var/local/emhttp/devs.ini"
	devsMap, err := parseIniSections(devsIniPath)
	if err == nil {
		for section, data := range devsMap {
			if len(data) == 0 {
				continue
			}

			d := domain.ArrayDisk{
				Id:         section,
				Name:       data["name"],
				Identifier: data["id"],
				Device:     data["device"],
				State:      "DISK_OK", // Usually Unassigned are OK if present
			}

			if val, ok := data["size"]; ok {
				fmt.Sscanf(val, "%d", &d.Size)
			}

			// Use robust parsing
			d.NumReads, d.NumWrites, d.NumErrors, d.ReadBytes, d.WriteBytes = parseStats(data)

			if val, ok := data["temp"]; ok && val != "*" {
				fmt.Sscanf(val, "%d", &d.Temp)
			}

			status.Unassigned = append(status.Unassigned, d)
		}
	}

	return status, nil
}

// Helper to parse simple Key=Value INI files (no sections, or flat)
func parseIniFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue // Skip comments and section headers for flat parser
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = strings.Trim(val, "\"")
		}
	}
	return result, scanner.Err()
}

// Helper to parse INI with Sections [SectionName]
func parseIniSections(path string) (map[string]map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]map[string]string)
	var currentSection string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Extract content between []
			rawSection := line[1 : len(line)-1]
			// Trim quotes if present (some Unraid INI files use ["section"])
			currentSection = strings.Trim(rawSection, "\"")
			result[currentSection] = make(map[string]string)
			continue
		}

		if currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				result[currentSection][key] = strings.Trim(val, "\"")
			}
		}
	}
	return result, scanner.Err()
}

// CalculateSpeeds updates the ReadSpeed/WriteSpeed fields based on difference from previous status
func CalculateSpeeds(curr *domain.ArrayStatus, prev *domain.ArrayStatus, deltaSeconds float64) {
	if deltaSeconds <= 0 {
		return
	}

	// Helper to index disks by name (unique)
	mapDisks := func(s *domain.ArrayStatus) map[string]domain.ArrayDisk {
		m := make(map[string]domain.ArrayDisk)
		for _, d := range s.Disks {
			m[d.Name] = d
		}
		for _, d := range s.Parities {
			m[d.Name] = d
		}
		for _, d := range s.Caches {
			m[d.Name] = d
		}
		for _, d := range s.Unassigned {
			m[d.Name] = d
		} // Name might be empty/dup? Use Id preferably
		// Unassigned usually have Id="Dev X" or similar.
		if s.Boot != nil {
			m["boot"] = *s.Boot
		}
		return m
	}

	prevMap := mapDisks(prev)

	updateSpeed := func(d *domain.ArrayDisk) {
		key := d.Name
		if d.Name == "" {
			key = d.Id
		} // Fallback
		if d == nil && curr.Boot != nil && d.Id == "flash" {
			key = "boot"
		} // Special case for boot being pointer math

		if p, ok := prevMap[key]; ok {
			// READS
			if d.ReadBytes > 0 && p.ReadBytes > 0 {
				diff := float64(d.ReadBytes - p.ReadBytes)
				if diff >= 0 {
					d.ReadSpeed = diff / deltaSeconds
				}
			} else {
				// Fallback: Estimate 4KB per IO
				diff := float64(d.NumReads - p.NumReads)
				if diff >= 0 {
					d.ReadSpeed = (diff * 4096.0) / deltaSeconds
				}
			}

			// WRITES
			if d.WriteBytes > 0 && p.WriteBytes > 0 {
				diff := float64(d.WriteBytes - p.WriteBytes)
				if diff >= 0 {
					d.WriteSpeed = diff / deltaSeconds
				}
			} else {
				// Fallback
				diff := float64(d.NumWrites - p.NumWrites)
				if diff >= 0 {
					d.WriteSpeed = (diff * 4096.0) / deltaSeconds
				}
			}
		}
	}

	for i := range curr.Disks {
		updateSpeed(&curr.Disks[i])
	}
	for i := range curr.Parities {
		updateSpeed(&curr.Parities[i])
	}
	for i := range curr.Caches {
		updateSpeed(&curr.Caches[i])
	}
	for i := range curr.Unassigned {
		updateSpeed(&curr.Unassigned[i])
	}
	if curr.Boot != nil {
		// Boot is a pointer, keys match "boot" in map
		// But in mapDisks, keys come from Name. Boot Name is 'flash'.
		// Map key logic: m["boot"] = *s.Boot
		// updateSpeed key logic check
		// Let's customize updateSpeed for Boot to avoid key confusion
		if p, ok := prevMap["boot"]; ok {
			d := curr.Boot
			// COPY PASTE LOGIC (refactor if messy)
			if d.ReadBytes > 0 && p.ReadBytes > 0 {
				d.ReadSpeed = float64(d.ReadBytes-p.ReadBytes) / deltaSeconds
			} else {
				d.ReadSpeed = float64(d.NumReads-p.NumReads) * 4096.0 / deltaSeconds
			}
			if d.WriteBytes > 0 && p.WriteBytes > 0 {
				d.WriteSpeed = float64(d.WriteBytes-p.WriteBytes) / deltaSeconds
			} else {
				d.WriteSpeed = float64(d.NumWrites-p.NumWrites) * 4096.0 / deltaSeconds
			}
		}
	}
}
