package vm

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"raidman/src/internal/domain"
)

// Helper to get IP
func GetVmIp(vmName string, mac string) string {
	// Try virsh domifaddr --source agent
	out, err := exec.Command("virsh", "domifaddr", vmName, "--source", "agent").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(mac)) {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					return strings.Split(fields[3], "/")[0] // Return IP without CIDR
				}
			}
		}
	}
	return ""
}

func GetVmDetailsXml(vmName string) (*domain.DomainXml, error) {
	out, err := exec.Command("virsh", "dumpxml", vmName).Output()
	if err != nil {
		return nil, err
	}
	var dom domain.DomainXml
	if err := xml.Unmarshal(out, &dom); err != nil {
		return nil, err
	}
	return &dom, nil
}

func GetVmInfo(vmName string) (*domain.VmInfo, error) {
	out, err := exec.Command("virsh", "dominfo", vmName).Output()
	if err != nil {
		return nil, err
	}

	// Parse general info first (existing logic)
	info := &domain.VmInfo{Name: vmName}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Id":
			info.DomId = val
		case "UUID":
			info.Uuid = val
		case "OS Type":
			info.OsType = val
		case "State":
			info.DetailedState = val
		case "CPU(s)":
			fmt.Sscanf(val, "%d", &info.Vcpus)
		case "CPU time":
			info.CpuTime = val
		case "Max memory":
			var memVal int64
			var unit string
			fmt.Sscanf(val, "%d %s", &memVal, &unit)
			if unit == "KiB" {
				info.Memory = memVal * 1024
			} else {
				info.Memory = memVal // Fallback
			}
		case "Persistent":
			info.Persistent = (val == "yes")
		case "Autostart":
			info.Autostart = (val == "enable")
		case "Managed save":
			info.ManagedSave = val
		case "Security model":
			info.SecurityModel = val
		case "Security DOI":
			info.SecurityDOI = val
		}
	}

	// NEW: Parse Detail XML
	xmlDetails, err := GetVmDetailsXml(vmName)
	if err == nil && xmlDetails != nil {
		// Extract Description
		if xmlDetails.Description != "" {
			info.Description = xmlDetails.Description
		}

		// Extract Icon from metadata
		if xmlDetails.Metadata.VmTemplate.Icon != "" {
			info.Icon = xmlDetails.Metadata.VmTemplate.Icon
		}

		// Populate Disks
		for _, d := range xmlDetails.DeviceList.Disks {
			src := d.Source.File
			if src == "" {
				src = d.Source.Dev
			}
			bootOrder := 0
			if d.Boot != nil {
				bootOrder = d.Boot.Order
			}
			info.Disks = append(info.Disks, domain.VmDisk{
				Source:    src,
				Target:    d.Target.Dev,
				Bus:       d.Target.Bus,
				Type:      d.Type,
				Serial:    d.Serial,
				BootOrder: bootOrder,
			})
		}

		// Populate Interfaces + IPs
		for _, i := range xmlDetails.DeviceList.Interfaces {
			src := i.Source.Bridge
			if src == "" {
				src = i.Source.Dev
			}
			// Fetch IP
			ip := GetVmIp(vmName, i.Mac.Address)

			info.Interfaces = append(info.Interfaces, domain.VmInterface{
				Mac:       i.Mac.Address,
				Model:     i.Model.Type,
				Network:   src,
				IpAddress: ip,
			})
		}

		// Populate Graphics
		for _, g := range xmlDetails.DeviceList.Graphics {
			info.Graphics = append(info.Graphics, domain.VmGraphics{
				Type: g.Type,
				Port: g.Port,
			})
		}
	}

	return info, nil
}

func SetVmAutostart(vmName string, enabled bool) error {
	args := []string{"autostart", vmName}
	if !enabled {
		args = []string{"autostart", "--disable", vmName}
	}
	return exec.Command("virsh", args...).Run()
}

func ParseVncDisplay(display string) (string, error) {
	// 1. Clean up input
	display = strings.TrimSpace(display)

	// 2. Handle "vnc://" prefix (e.g. "vnc://127.0.0.1:0" or "vnc://localhost:0")
	if strings.HasPrefix(display, "vnc://") {
		// Remove "vnc://"
		display = strings.TrimPrefix(display, "vnc://")

		lastColon := strings.LastIndex(display, ":")
		if lastColon == -1 {
			return "", fmt.Errorf("invalid vnc URI format (no colon): %s", display)
		}

		display = display[lastColon:] // includes the colon, e.g. ":0"
	}

	// 3. Handle ":0" format (shorthand)
	if strings.HasPrefix(display, ":") {
		displayNumStr := display[1:]
		var d int
		_, err := fmt.Sscan(displayNumStr, &d)
		if err != nil {
			return "", fmt.Errorf("invalid display number: %s", displayNumStr)
		}
		// Port is 5900 + display
		return fmt.Sprintf("%d", 5900+d), nil
	}

	return "", fmt.Errorf("unknown display format: %s", display)
}

func GetVncPort(vmName string) (string, error) {
	out, err := exec.Command("virsh", "domdisplay", vmName).Output()
	if err != nil {
		return "", err
	}

	return ParseVncDisplay(string(out))
}
