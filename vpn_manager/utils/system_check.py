"""
System Check module with comprehensive platform and dependency verification
"""

import platform
import os
import sys
import subprocess
import shutil
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def is_linux() -> bool:
    """Check if running on Linux"""
    return platform.system().lower() == 'linux'


def is_root() -> bool:
    """Check if running with root privileges"""
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def is_windows() -> bool:
    """Check if running on Windows"""
    return platform.system().lower() == 'windows'


def is_macos() -> bool:
    """Check if running on macOS"""
    return platform.system().lower() == 'darwin'


def get_linux_distribution() -> Optional[str]:
    """Get Linux distribution name"""
    if not is_linux():
        return None
    
    try:
        # Try reading /etc/os-release
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"')
        
        # Fallback to lsb_release
        result = subprocess.run(
            ['lsb_release', '-i', '-s'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip().lower()
        
    except Exception:
        return 'unknown'


def check_command_exists(command: str) -> bool:
    """
    Check if a command exists in PATH
    
    Args:
        command: Command name to check
        
    Returns:
        bool: True if command exists
    """
    return shutil.which(command) is not None


def check_required_commands() -> Tuple[bool, List[str]]:
    """
    Check if all required system commands are available
    
    Returns:
        Tuple of (all_present, missing_commands)
    """
    required_commands = {
        'linux': [
            'iptables',
            'ip6tables',
            'iptables-save',
            'iptables-restore',
            'ip',
            'ping',
            'route'
        ],
        'darwin': [
            'pfctl',
            'ifconfig',
            'ping',
            'netstat'
        ],
        'windows': [
            'netsh',
            'ipconfig',
            'ping',
            'route'
        ]
    }
    
    system = platform.system().lower()
    commands = required_commands.get(system, [])
    
    missing = []
    for cmd in commands:
        if not check_command_exists(cmd):
            missing.append(cmd)
    
    return len(missing) == 0, missing


def check_openvpn_installed() -> Tuple[bool, Optional[str]]:
    """
    Check if OpenVPN is installed
    
    Returns:
        Tuple of (installed, version)
    """
    if not check_command_exists('openvpn'):
        return False, None
    
    try:
        result = subprocess.run(
            ['openvpn', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Parse version from output
        version_line = result.stdout.split('\n')[0]
        version = version_line.split()[1] if len(version_line.split()) > 1 else 'unknown'
        
        return True, version
        
    except Exception as e:
        logger.warning(f"Failed to get OpenVPN version: {e}")
        return True, 'unknown'


def check_wireguard_installed() -> Tuple[bool, Optional[str]]:
    """
    Check if WireGuard is installed
    
    Returns:
        Tuple of (installed, version)
    """
    commands = ['wg', 'wg-quick']
    
    for cmd in commands:
        if not check_command_exists(cmd):
            return False, None
    
    try:
        result = subprocess.run(
            ['wg', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        version = result.stdout.strip().split()[-1] if result.stdout else 'unknown'
        return True, version
        
    except Exception:
        return True, 'unknown'


def check_python_packages() -> Dict[str, bool]:
    """
    Check if required Python packages are installed
    
    Returns:
        Dict of package: installed status
    """
    packages = {
        'yaml': False,
        'requests': False,
        'rich': False,
        'dnspython': False
    }
    
    # Check YAML
    try:
        import yaml
        packages['yaml'] = True
    except ImportError:
        pass
    
    # Check requests
    try:
        import requests
        packages['requests'] = True
    except ImportError:
        pass
    
    # Check rich
    try:
        import rich
        packages['rich'] = True
    except ImportError:
        pass
    
    # Check dnspython
    try:
        import dns
        packages['dnspython'] = True
    except ImportError:
        pass
    
    return packages


def check_network_capabilities() -> Dict[str, bool]:
    """
    Check network-related capabilities
    
    Returns:
        Dict of capability: available status
    """
    capabilities = {
        'can_modify_routes': False,
        'can_modify_dns': False,
        'can_modify_firewall': False,
        'ipv4_enabled': True,
        'ipv6_enabled': True
    }
    
    # Check if we can modify routes, DNS, and firewall (needs root on Linux)
    if is_linux():
        capabilities['can_modify_routes'] = is_root()
        capabilities['can_modify_dns'] = is_root()
        capabilities['can_modify_firewall'] = is_root()
        
        # Check IPv6
        try:
            with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as f:
                capabilities['ipv6_enabled'] = f.read().strip() == '0'
        except Exception:
            pass
    
    elif is_windows():
        # On Windows, check if running as administrator
        try:
            import ctypes
            capabilities['can_modify_routes'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            capabilities['can_modify_dns'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            capabilities['can_modify_firewall'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    
    elif is_macos():
        capabilities['can_modify_routes'] = is_root()
        capabilities['can_modify_dns'] = is_root()
        capabilities['can_modify_firewall'] = is_root()
    
    return capabilities


def get_system_info() -> Dict:
    """Get comprehensive system information"""
    info = {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'is_root': is_root(),
        'is_linux': is_linux(),
        'is_windows': is_windows(),
        'is_macos': is_macos()
    }
    
    # Add Linux-specific info
    if is_linux():
        info['linux_distribution'] = get_linux_distribution()
    
    # Check commands
    all_commands_present, missing = check_required_commands()
    info['required_commands_present'] = all_commands_present
    info['missing_commands'] = missing
    
    # Check VPN software
    ovpn_installed, ovpn_version = check_openvpn_installed()
    info['openvpn_installed'] = ovpn_installed
    info['openvpn_version'] = ovpn_version
    
    wg_installed, wg_version = check_wireguard_installed()
    info['wireguard_installed'] = wg_installed
    info['wireguard_version'] = wg_version
    
    # Check Python packages
    info['python_packages'] = check_python_packages()
    
    # Check network capabilities
    info['network_capabilities'] = check_network_capabilities()
    
    return info


def verify_system_requirements() -> Tuple[bool, List[str]]:
    """
    Verify all system requirements are met
    
    Returns:
        Tuple of (requirements_met, error_messages)
    """
    errors = []
    
    # Check platform
    if not (is_linux() or is_macos() or is_windows()):
        errors.append("Unsupported platform")
    
    # Check Python version
    py_version = sys.version_info
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 7):
        errors.append("Python 3.7 or higher required")
    
    # Check required commands
    all_present, missing = check_required_commands()
    if not all_present:
        errors.append(f"Missing required commands: {', '.join(missing)}")
    
    # Check for at least one VPN client
    ovpn_installed, _ = check_openvpn_installed()
    wg_installed, _ = check_wireguard_installed()
    
    if not (ovpn_installed or wg_installed):
        errors.append("No VPN client found (OpenVPN or WireGuard required)")
    
    # Check network capabilities
    capabilities = check_network_capabilities()
    if is_linux() and not capabilities['can_modify_firewall']:
        errors.append("Insufficient privileges for kill switch (root required)")
    
    # Check critical Python packages
    packages = check_python_packages()
    if not packages['yaml']:
        errors.append("PyYAML package not installed")
    
    return len(errors) == 0, errors


def print_system_info():
    """Print system information to console"""
    info = get_system_info()
    
    print("System Information:")
    print(f"  Platform: {info['platform']} {info['platform_release']}")
    print(f"  Machine: {info['machine']}")
    print(f"  Python: {info['python_version']}")
    print(f"  Root/Admin: {info['is_root']}")
    
    if info.get('linux_distribution'):
        print(f"  Distribution: {info['linux_distribution']}")
    
    print("\nVPN Software:")
    if info['openvpn_installed']:
        print(f"  OpenVPN: {info['openvpn_version']}")
    else:
        print("  OpenVPN: Not installed")
    
    if info['wireguard_installed']:
        print(f"  WireGuard: {info['wireguard_version']}")
    else:
        print("  WireGuard: Not installed")
    
    print("\nRequired Commands:")
    if info['required_commands_present']:
        print("  All required commands available")
    else:
        print(f"  Missing: {', '.join(info['missing_commands'])}")
    
    print("\nPython Packages:")
    for package, installed in info['python_packages'].items():
        status = "Installed" if installed else "Missing"
        print(f"  {package}: {status}")
    
    print("\nNetwork Capabilities:")
    for cap, available in info['network_capabilities'].items():
        status = "Yes" if available else "No"
        print(f"  {cap}: {status}")
    
    # Verify requirements
    requirements_met, errors = verify_system_requirements()
    
    print("\nSystem Requirements:")
    if requirements_met:
        print("  All requirements met")
    else:
        print("  Issues found:")
        for error in errors:
            print(f"    - {error}")


if __name__ == '__main__':
    print_system_info()

