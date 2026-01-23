package array

import (
	"os"
	"strconv"
	"strings"
)

type ParityCheckHistory struct {
	Date     string `json:"date"`
	Duration int64  `json:"duration"`
	Speed    string `json:"speed"`
	Status   string `json:"status"`
	Errors   int    `json:"errors"`
}

func GetParityHistory() ([]ParityCheckHistory, error) {
	path := "/boot/config/parity-checks.log"
	content, err := os.ReadFile(path)
	if err != nil {
		return []ParityCheckHistory{}, nil // Return empty if not found, don't error out entire request
	}

	var history []ParityCheckHistory
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")

	// File is typically chronological, but we want newest first?
	// unraid-api does .reverse()
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if line == "" {
			continue
		}

		// Format: date|duration|speed|status|errors
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}

		dateStr := parts[0]
		durationStr := parts[1]
		speed := parts[2]
		statusStr := parts[3]
		errorsStr := "0"
		if len(parts) > 4 {
			errorsStr = parts[4]
		}

		duration, _ := strconv.ParseInt(durationStr, 10, 64)
		errors, _ := strconv.Atoi(errorsStr)

		// Map status code to string if needed, or keep as is?
		// unraid-api: 0 = COMPLETED, -4 = CANCELLED, etc.
		// Let's pass the raw string/status for now, or map it.
		// Client expects "COMPLETED", "CANCELLED"?
		// Actually unraid-api maps:
		// 0 -> COMPLETED, -4 -> CANCELLED, else FAILED
		// But the log file might contain text or number?
		// unraid-api parses it as number.

		statusNum, _ := strconv.Atoi(statusStr)
		status := "FAILED"
		if statusNum == 0 {
			status = "COMPLETED"
		} else if statusNum == -4 {
			status = "CANCELLED"
		}

		history = append(history, ParityCheckHistory{
			Date:     dateStr, // ISO string or whatever is in log
			Duration: duration,
			Speed:    speed,
			Status:   status,
			Errors:   errors,
		})
	}

	return history, nil
}
