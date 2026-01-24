# VPN Manager

A professional-grade VPN management system with advanced security features, kill switch functionality, and IP rotation capabilities. Built for Linux systems requiring robust VPN connection management with enterprise-level security.

## Features

- **Multi-Protocol Support**: OpenVPN and WireGuard compatibility
- **Advanced Kill Switch**: Linux iptables-based traffic filtering to prevent leaks
- **IP Rotation**: Seamless server switching with connection preservation
- **DNS Leak Protection**: Secures DNS queries through VPN tunnel
- **Automatic Reconnection**: Smart reconnect with exponential backoff
- **Real-time Monitoring**: Connection health checks and statistics
- **Rich CLI Interface**: Beautiful terminal output with progress indicators
- **Flexible Configuration**: YAML/JSON configuration support

## System Requirements

- **Operating System**: Linux (kill switch requires Linux iptables)
- **Python**: 3.8 or higher
- **Privileges**: Root access for kill switch functionality
- **Dependencies**: OpenVPN/WireGuard binaries

### Required System Packages

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install openvpn wireguard-tools iptables
```

#### RHEL/CentOS/Fedora
```bash
sudo yum install openvpn wireguard-tools iptables
# or on Fedora
sudo dnf install openvpn wireguard-tools iptables
```

## Installation

### Method 1: Install from Source
```bash
git clone https://github.com/yourusername/vpn-manager.git
cd vpn-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Method 2: Direct Installation
```bash
git clone https://github.com/yourusername/vpn-manager.git
cd vpn-manager
pip install .
```

## Configuration

### 1. Create Configuration Directory
```bash
mkdir -p ~/.config/vpn-manager
```

### 2. Copy Example Configuration
```bash
cp config.json ~/.config/vpn-manager/
cp -r config/vpn_profiles ~/.config/vpn-manager/
cp config/settings.yaml ~/.config/vpn-manager/
```

### 3. Configure VPN Providers

Edit `~/.config/vpn-manager/config.json`:
```json
{
  "default_protocol": "udp",
  "default_port": 1194,
  "kill_switch_enabled": true,
  "auto_reconnect": true,
  "dns_servers": ["1.1.1.1", "8.8.8.8"],
  "vpn_providers": {
    "your_provider": {
      "api_url": "https://api.yourvpn.com/servers",
      "auth_token": "your_api_token_here",
      "config_dir": "~/.config/vpn-manager/providers/your_provider"
    }
  }
}
```

### 4. Add VPN Configuration Files

Place your `.ovpn` configuration files in `~/.config/vpn-manager/vpn_profiles/`:
```bash
# Example files
~/.config/vpn-manager/vpn_profiles/netherlands.ovpn
~/.config/vpn-manager/vpn_profiles/us-east.ovpn
~/.config/vpn-manager/vpn_profiles/germany.ovpn
```

## Usage

### Command Line Interface

#### Basic Connection
```bash
# Connect to a specific location
vpn-manager connect --location "Netherlands" --protocol udp

# Connect with custom config file
vpn-manager connect --config ~/.config/vpn-manager/custom.ovpn

# Connect without kill switch
vpn-manager connect --location "US" --no-kill-switch
```

#### IP Rotation
```bash
# Rotate to a random server
vpn-manager rotate --random

# Rotate to specific location
vpn-manager rotate --location "Germany"

# Force rotation even if connected
vpn-manager rotate --force
```

#### Status and Monitoring
```bash
# Check basic status
vpn-manager status

# Check detailed status with statistics
vpn-manager status --detailed

# List available servers
vpn-manager list --country US
```

#### Testing and Diagnostics
```bash
# Test for DNS/IP leaks
vpn-manager test --leak-test

# Run speed test
vpn-manager test --speed-test

# Both tests together
vpn-manager test --leak-test --speed-test
```

#### Disconnection
```bash
# Disconnect normally
vpn-manager disconnect

# Disconnect but keep kill switch active
vpn-manager disconnect --kill-switch
```

### Advanced Usage

#### Custom DNS Servers
```bash
vpn-manager connect --location "US" --dns 1.1.1.1 8.8.8.8 9.9.9.9
```

#### Specific Server Selection
```bash
vpn-manager connect --server us-east1.example.com --port 1194
```

#### Programmatic Usage
```python
from vpn_manager.core.vpn_controller import VPNController
from vpn_manager.core.types import VPNServer

# Initialize controller
controller = VPNController()

# Create server configuration
server = VPNServer(
    id="nl-ams-01",
    hostname="nl-amsterdam.vpn.com",
    ip_address="192.168.1.1",
    country="Netherlands",
    city="Amsterdam",
    protocol="udp",
    port=1194
)

# Connect with kill switch
controller.connect(server, enable_kill_switch=True)

# Get status
status = controller.get_status()
print(f"Connected: {status['connected']}")
print(f"IP: {status['statistics']['ip_address']}")

# Disconnect
controller.disconnect()
```

## Configuration Options

### Main Settings (`settings.yaml`)

```yaml
# General settings
debug: false
log_level: INFO
log_file: logs/vpn_manager.log

# VPN settings
default_protocol: openvpn
auto_reconnect: true
reconnect_interval: 30
connection_timeout: 60

# Kill switch settings
kill_switch:
  enabled: true
  strict_mode: false
  allowed_interfaces: ["lo", "docker0"]

# IP rotation settings
ip_rotation:
  enabled: false
  interval: 3600
  random_location: true

# DNS settings
dns:
  leak_protection: true
  custom_servers: []
  
# Monitoring settings
monitoring:
  enabled: true
  check_interval: 30
  health_check_url: "https://httpbin.org/ip"
```

## Security Features

### Kill Switch
The kill switch uses Linux iptables to:
- Block all non-VPN traffic when VPN is disconnected
- Prevent DNS leaks by filtering DNS queries
- Support both IPv4 and IPv6 traffic filtering
- Allow specific interfaces (e.g., loopback, Docker)

### DNS Leak Protection
- Forces DNS queries through VPN tunnel
- Supports custom DNS servers
- Validates DNS resolution through VPN
- Automatic fallback to secure DNS servers

### IPv6 Protection
- Complete IPv6 traffic blocking when IPv4 VPN is active
- Prevents IPv6 leakage in dual-stack environments
- Automatic interface detection and filtering

## Troubleshooting

### Common Issues

#### Kill Switch Not Working
```bash
# Check if running as root
sudo vpn-manager connect --location "US"

# Check iptables rules
sudo iptables -L -n -v

# Reset kill switch rules
sudo vpn-manager disconnect --kill-switch-reset
```

#### Connection Failures
```bash
# Enable debug logging
vpn-manager connect --location "US" --debug

# Check OpenVPN installation
openvpn --version

# Test with manual config
sudo openvpn --config ~/.config/vpn-manager/vpn_profiles/test.ovpn
```

#### DNS Leaks
```bash
# Test DNS resolution
nslookup google.com

# Check resolv.conf
cat /etc/resolv.conf

# Test with custom DNS
vpn-manager test --leak-test --dns 1.1.1.1
```

### Log Files
- Main log: `~/.config/vpn-manager/logs/vpn_manager.log`
- Debug logs: `~/.config/vpn-manager/logs/debug.log`
- Connection logs: `~/.config/vpn-manager/logs/connection.log`

## Development

### Running Tests
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=vpn_manager --cov-report=html

# Run specific test file
pytest tests/test_vpn_controller.py
```

### Code Quality
```bash
# Format code
black vpn_manager/

# Lint code
flake8 vpn_manager/

# Type checking
mypy vpn_manager/
```

### Project Structure
```
vpn_manager/
├── core/                   # Core business logic
│   ├── vpn_controller.py   # Main VPN state management
│   ├── kill_switch.py      # Kill switch implementation
│   ├── ip_rotator.py       # IP rotation logic
│   ├── config_manager.py   # Configuration management
│   └── types.py           # Type definitions
├── providers/             # VPN protocol implementations
│   ├── openvpn_client.py  # OpenVPN client wrapper
│   └── wireguard_client.py # WireGuard client wrapper
├── utils/                 # Utility modules
│   ├── network_tools.py   # Network diagnostics
│   ├── logging_setup.py   # Logging configuration
│   └── system_check.py    # System compatibility
└── cli/                   # Command-line interface
    └── interface.py       # Rich-based CLI implementation
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

- **Root Privileges**: Kill switch functionality requires root privileges
- **Network Isolation**: Always test kill switch in isolated environment
- **Configuration Security**: Store API tokens and credentials securely
- **Audit Logging**: Monitor logs for unusual connection patterns
- **Regular Updates**: Keep OpenVPN/WireGuard binaries updated

## Support

For issues and questions:
- Create an issue on GitHub
- Check existing documentation
- Review log files for error details

## Changelog

### v0.1.0
- Initial release
- OpenVPN support
- Basic kill switch implementation
- CLI interface
- IP rotation functionality
- DNS leak protection

---

**Disclaimer**: This software is provided as-is. Users are responsible for ensuring compliance with local laws and VPN provider terms of service.