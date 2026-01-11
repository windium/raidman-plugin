package array

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"raidman/src/internal/domain"
)

func GetArrayStatus() (*domain.ArrayStatus, error) {
	// Parse var.ini for global status
	varIni, err := parseIniFile("/var/local/emhttp/var.ini")
	if err != nil {
		// If on dev machine/fallback
		if os.IsNotExist(err) {
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
					{Id: "1", Name: "disk1", Device: "sdc", State: "DISK_OK", Size: 1000000000, NumReads: 789, NumWrites: 101},
				},
				Caches: []domain.ArrayDisk{
					{Id: "cache", Name: "cache", Device: "nvme0n1", State: "DISK_OK", Size: 500000000, NumReads: 999, NumWrites: 888},
				},
			}, nil
		}
		return nil, err
	}

	// Parse disks.ini for disk details
	disksSections, err := parseIniSections("/var/local/emhttp/disks.ini")
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

	// MAPPING VAR.INI (Global Status)
	if val, ok := varIni["mdState"]; ok {
		status.State = strings.Trim(val, "\"")
	}

	// Parity Check Details from var.ini
	if val, ok := varIni["mdResync"]; ok {
		fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Total)
	}
	if val, ok := varIni["mdResyncPos"]; ok {
		fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Pos)
	}
	if val, ok := varIni["mdResyncCorr"]; ok {
		fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Errors)
	}
	if val, ok := varIni["sbSynced"]; ok {
		status.ParityCheckStatus.Date = val
	}
	if val, ok := varIni["mdResyncDt"]; ok {
		fmt.Sscanf(val, "%d", &status.ParityCheckStatus.Duration)
	}
	if val, ok := varIni["mdResyncSp"]; ok {
		status.ParityCheckStatus.Speed = val
	}

	// Calculate Running Status
	if status.ParityCheckStatus.Total > 0 && status.ParityCheckStatus.Pos > 0 && status.ParityCheckStatus.Pos < status.ParityCheckStatus.Total {
		status.ParityCheckStatus.Running = true
		status.ParityCheckStatus.Status = "RUNNING"
		// Check mdState for PAUSED? mdState usually "STARTED" even if paused,
		// but sometimes there is a separate state. For now assume RUNNING if pos < total.
		pct := float64(status.ParityCheckStatus.Pos) / float64(status.ParityCheckStatus.Total) * 100.0
		status.ParityCheckStatus.Progress = fmt.Sprintf("%.1f", pct)
	} else {
		status.ParityCheckStatus.Running = false
		status.ParityCheckStatus.Status = "IDLE"
		status.ParityCheckStatus.Progress = "100.0"
	}

	// MAPPING DISKS.INI (Per Disk)
	for sectionName, data := range disksSections {
		d := domain.ArrayDisk{
			Id: sectionName, // Use section name as temporary ID, might overlap w/ Name
		}

		if val, ok := data["name"]; ok {
			d.Name = strings.Trim(val, "\"")
		}
		if d.Name == "" {
			d.Name = sectionName // Fallback
		}

		if val, ok := data["device"]; ok {
			d.Device = strings.Trim(val, "\"")
		}
		if val, ok := data["status"]; ok {
			d.State = strings.Trim(val, "\"")
		}
		if val, ok := data["size"]; ok {
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &d.Size)
		}
		if val, ok := data["idx"]; ok {
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &d.Idx)
		}
		if val, ok := data["temp"]; ok {
			// temp might be "34 C" or just "34" or "*"
			var temp int
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &temp)
			d.Temp = temp
		}

		// READS / WRITES / ERRORS
		if val, ok := data["numReads"]; ok {
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &d.NumReads)
		}
		if val, ok := data["numWrites"]; ok {
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &d.NumWrites)
		}
		if val, ok := data["numErrors"]; ok {
			fmt.Sscanf(strings.Trim(val, "\""), "%d", &d.NumErrors)
		}

		// Categorize
		if strings.HasPrefix(d.Name, "parity") {
			status.Parities = append(status.Parities, d)
		} else if strings.HasPrefix(d.Name, "cache") || strings.HasPrefix(d.Name, "pool") {
			status.Caches = append(status.Caches, d)
		} else {
			// Array disk?
			if strings.HasPrefix(d.Name, "disk") {
				status.Disks = append(status.Disks, d)
			} else {
				if d.Name == "flash" {
					continue
				}
				status.Caches = append(status.Caches, d)
			}
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
			currentSection = line[1 : len(line)-1]
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
