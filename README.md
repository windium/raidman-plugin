# Raidman Unraid Plugin

Remote management plugin for Unraid servers, providing real-time monitoring and control for the Raidman mobile app.

> [!WARNING]
> Please read the [Security Guide](SECURITY.md) before installation.

## Features
- 🔐 **Secure Authentication**: Granular permissions & audit logging.
- 🖥️ **Terminal & VNC**: Secure access to host/containers/VMs.
- 📊 **Real-time Monitoring**: Docker, VM, and Array stats.
- 🐳 **Management**: Full control over Docker containers and VMs.

## Installation
1. Install via Unraid Community Applications (or use URL: `https://raw.githubusercontent.com/windium/raidman-plugin/main/raidman.plg`)
2. Go to **Settings → Management Access → API Keys**
3. Create a key with: `docker:read`, `docker:update`, `vm:read`, `vm:update`, `array:read`.

> [!NOTE]
> Terminal access requires **ADMIN** role. VNC requires `vm:update`.

## Monitoring & Troubleshooting
- **Logs**: `tail -f /var/log/raidman.log`
- **Security Events**: `grep "AUDIT" /var/log/raidman.log`

## Support
- **Issues**: [GitHub Issues](https://github.com/windium/raidman-plugin/issues)
- **Security**: security@raidman.app
