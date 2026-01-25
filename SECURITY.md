# Security Guide

## Overview
Raidman prioritizes security with API key validation, granular permissions, rate limiting, and audit logging.

## Authentication & Permissions
Raidman uses Unraid's native permission system.

### Recommended Permissions
- **Docker**: `docker:read`, `docker:update`
- **VMs**: `vm:read`, `vm:update`
- **Array**: `array:read`

> [!IMPORTANT]
> **Terminal Access**: Requires the **ADMIN** role.
> **VNC Access**: Requires `vm:update` permission.

## Network Security
- **Local Access**: Recommended. No extra config needed.
- **Remote Access**: Use a VPN (WireGuard/Tailscale).
- **Avoid**: Port forwarding or exposing directly to the internet.

## Best Practices
- Rotate API keys regularly.
- Monitor logs at `/var/log/raidman.log`.
- Report security issues to security@raidman.app.
