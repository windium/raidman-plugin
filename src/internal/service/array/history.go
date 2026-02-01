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
		return []ParityCheckHistory{}, nil
	}

	var history []ParityCheckHistory
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")

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

		statusNum, _ := strconv.Atoi(statusStr)
		status := "FAILED"
		if statusNum == 0 {
			status = "COMPLETED"
		} else if statusNum == -4 {
			status = "CANCELLED"
		}

		history = append(history, ParityCheckHistory{
			Date:     dateStr,
			Duration: duration,
			Speed:    speed,
			Status:   status,
			Errors:   errors,
		})
	}

	return history, nil
}
