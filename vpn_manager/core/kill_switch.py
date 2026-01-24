"""
Advanced kill switch using iptables/nftables with improved error handling
"""

import subprocess
import threading
import time
from typing import List, Dict, Optional, Set
from pathlib import Path
import logging
import json

from ..utils.system_check import is_linux, is_root
from ..utils.network_tools import NetworkTools

logger = logging.getLogger(__name__)


class KillSwitchError(Exception):
    """Custom exception for kill switch errors"""
    pass


class KillSwitch:
    """Advanced kill switch to prevent traffic leaks"""
    
    def __init__(self, interface: str = 'tun+', backup_interface: str = 'wg+'):
        """
        Initialize kill switch
        
        Args:
            interface: Primary VPN interface pattern (e.g., 'tun+')
            backup_interface: Backup VPN interface pattern (e.g., 'wg+')
        """
        self.interface = interface
        self.backup_interface = backup_interface
        self.active = False
        self._lock = threading.RLock()
        self.network_tools = NetworkTools()
        
        # Store original rules for restoration
        self.original_rules = {
            'iptables': {'filter': '', 'nat': '', 'mangle': ''},
            'ip6tables': {'filter': '', 'nat': '', 'mangle': ''}
        }
        
        # DNS servers to allow
        self.allowed_dns: Set[str] = {'1.1.1.1', '8.8.8.8', '9.9.9.9'}
        
        # VPN servers to allow
        self.allowed_vpn_servers: List[Dict[str, any]] = []
        
        # Local network ranges (will be populated)
        self.local_networks: List[str] = []
        
        # Backup file for rules
        self.backup_file = Path('/tmp/vpn_killswitch_backup.json')
        
        if not is_linux():
            raise KillSwitchError("Kill switch only supported on Linux")
        
        if not is_root():
            raise KillSwitchError("Kill switch requires root privileges")
        
        # Check for required tools
        self._check_requirements()
    
    def _check_requirements(self):
        """Check if required tools are available"""
        required_tools = ['iptables', 'ip6tables', 'iptables-save', 'iptables-restore']
        
        for tool in required_tools:
            try:
                subprocess.run(
                    ['which', tool],
                    check=True,
                    capture_output=True
                )
            except subprocess.CalledProcessError:
                raise KillSwitchError(f"Required tool '{tool}' not found")
    
    def add_vpn_server(self, ip: str, protocol: str = 'udp', port: int = 1194):
        """
        Add VPN server to allowed list
        
        Args:
            ip: Server IP address or hostname
            protocol: Protocol (udp/tcp)
            port: Port number
        """
        server = {
            'ip': ip,
            'protocol': protocol.lower(),
            'port': port
        }
        
        if server not in self.allowed_vpn_servers:
            self.allowed_vpn_servers.append(server)
            logger.debug(f"Added VPN server: {ip}:{port}/{protocol}")
    
    def add_dns_server(self, dns: str):
        """Add DNS server to allowed list"""
        self.allowed_dns.add(dns)
        logger.debug(f"Added DNS server: {dns}")
    
    def enable(self, force: bool = False, allow_lan: bool = True) -> bool:
        """
        Enable kill switch
        
        Args:
            force: Force enable even if already active
            allow_lan: Allow local network traffic
            
        Returns:
            bool: True if successful
        """
        with self._lock:
            if self.active and not force:
                logger.warning("Kill switch already active")
                return True
            
            logger.info("Enabling kill switch...")
            
            try:
                # Backup current rules
                if not self._backup_rules():
                    logger.error("Failed to backup rules, aborting")
                    return False
                
                # Get current network information
                current_dns = self.network_tools.get_current_dns()
                self.allowed_dns.update(current_dns)
                
                gateway = self.network_tools.get_default_gateway()
                
                if allow_lan:
                    self._detect_local_networks()
                
                # Flush existing rules
                self._flush_rules()
                
                # Apply kill switch rules
                self._apply_ipv4_rules(gateway, allow_lan)
                self._apply_ipv6_rules()
                
                # Verify rules are applied
                if not self._verify_rules():
                    logger.error("Rule verification failed")
                    self._restore_rules()
                    return False
                
                # Save state
                self._save_state()
                
                self.active = True
                logger.info("Kill switch enabled successfully")
                return True
                
            except Exception as e:
                logger.error(f"Failed to enable kill switch: {e}", exc_info=True)
                self._restore_rules()
                return False
    
    def disable(self) -> bool:
        """Disable kill switch and restore original rules"""
        with self._lock:
            if not self.active:
                logger.debug("Kill switch already disabled")
                return True
            
            logger.info("Disabling kill switch...")
            
            try:
                self._restore_rules()
                self._cleanup_state()
                self.active = False
                logger.info("Kill switch disabled successfully")
                return True
            except Exception as e:
                logger.error(f"Failed to disable kill switch: {e}", exc_info=True)
                return False
    
    def is_active(self) -> bool:
        """Check if kill switch is active"""
        return self.active
    
    def _detect_local_networks(self):
        """Detect local network ranges"""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.local_networks = []
            for line in result.stdout.split('\n'):
                if 'link' in line or 'scope link' in line:
                    parts = line.split()
                    if parts and '/' in parts[0]:
                        self.local_networks.append(parts[0])
            
            logger.debug(f"Detected local networks: {self.local_networks}")
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to detect local networks: {e}")
    
    def _backup_rules(self) -> bool:
        """Backup current iptables rules"""
        try:
            backup_data = {
                'timestamp': time.time(),
                'iptables': {},
                'ip6tables': {}
            }
            
            for table in ['filter', 'nat', 'mangle']:
                # IPv4
                try:
                    result = subprocess.run(
                        ['iptables-save', '-t', table],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10
                    )
                    self.original_rules['iptables'][table] = result.stdout
                    backup_data['iptables'][table] = result.stdout
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to backup iptables table {table}: {e}")
                
                # IPv6
                try:
                    result = subprocess.run(
                        ['ip6tables-save', '-t', table],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10
                    )
                    self.original_rules['ip6tables'][table] = result.stdout
                    backup_data['ip6tables'][table] = result.stdout
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to backup ip6tables table {table}: {e}")
            
            # Save to file
            with open(self.backup_file, 'w') as f:
                json.dump(backup_data, f)
            
            logger.debug("Rules backed up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup rules: {e}")
            return False
    
    def _restore_rules(self):
        """Restore original iptables rules"""
        try:
            logger.info("Restoring original firewall rules...")
            
            # First, try to restore from memory
            restored = False
            
            for table in ['filter', 'nat', 'mangle']:
                # IPv4
                if self.original_rules['iptables'].get(table):
                    try:
                        subprocess.run(
                            ['iptables-restore', '-T', table],
                            input=self.original_rules['iptables'][table],
                            text=True,
                            check=True,
                            timeout=10
                        )
                        restored = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to restore iptables table {table}: {e}")
                
                # IPv6
                if self.original_rules['ip6tables'].get(table):
                    try:
                        subprocess.run(
                            ['ip6tables-restore', '-T', table],
                            input=self.original_rules['ip6tables'][table],
                            text=True,
                            check=True,
                            timeout=10
                        )
                        restored = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to restore ip6tables table {table}: {e}")
            
            # If memory restore failed, try from backup file
            if not restored and self.backup_file.exists():
                logger.info("Attempting restore from backup file...")
                with open(self.backup_file, 'r') as f:
                    backup_data = json.load(f)
                
                for table in ['filter', 'nat', 'mangle']:
                    if backup_data['iptables'].get(table):
                        subprocess.run(
                            ['iptables-restore', '-T', table],
                            input=backup_data['iptables'][table],
                            text=True,
                            check=True,
                            timeout=10
                        )
                    
                    if backup_data['ip6tables'].get(table):
                        subprocess.run(
                            ['ip6tables-restore', '-T', table],
                            input=backup_data['ip6tables'][table],
                            text=True,
                            check=True,
                            timeout=10
                        )
            
            # If all else fails, do emergency recovery
            if not restored:
                logger.warning("Standard restore failed, attempting emergency recovery...")
                self._emergency_recovery()
            
            logger.info("Original rules restored")
            
        except Exception as e:
            logger.error(f"Failed to restore rules: {e}")
            self._emergency_recovery()
    
    def _flush_rules(self):
        """Flush iptables rules"""
        flush_commands = [
            # IPv4
            ['iptables', '-F'],
            ['iptables', '-t', 'nat', '-F'],
            ['iptables', '-t', 'mangle', '-F'],
            ['iptables', '-X'],
            ['iptables', '-t', 'nat', '-X'],
            ['iptables', '-t', 'mangle', '-X'],
            ['iptables', '-P', 'INPUT', 'ACCEPT'],
            ['iptables', '-P', 'FORWARD', 'ACCEPT'],
            ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
            
            # IPv6
            ['ip6tables', '-F'],
            ['ip6tables', '-t', 'nat', '-F'],
            ['ip6tables', '-t', 'mangle', '-F'],
            ['ip6tables', '-X'],
            ['ip6tables', '-t', 'nat', '-X'],
            ['ip6tables', '-t', 'mangle', '-X'],
            ['ip6tables', '-P', 'INPUT', 'ACCEPT'],
            ['ip6tables', '-P', 'FORWARD', 'ACCEPT'],
            ['ip6tables', '-P', 'OUTPUT', 'ACCEPT'],
        ]
        
        for cmd in flush_commands:
            try:
                subprocess.run(cmd, check=True, timeout=5)
            except subprocess.CalledProcessError:
                pass
    
    def _apply_ipv4_rules(self, gateway: Optional[str], allow_lan: bool):
        """Apply IPv4 kill switch rules"""
        
        def run_iptables(cmd: List[str]):
            """Execute iptables command with error handling"""
            try:
                subprocess.run(
                    ['iptables'] + cmd,
                    check=True,
                    capture_output=True,
                    timeout=5
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"iptables command failed: {' '.join(cmd)}: {e.stderr}")
                raise
        
        # Allow loopback
        run_iptables(['-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
        run_iptables(['-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'])
        
        # Allow established connections
        run_iptables([
            '-A', 'INPUT', '-m', 'conntrack',
            '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'
        ])
        run_iptables([
            '-A', 'OUTPUT', '-m', 'conntrack',
            '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'
        ])
        
        # Allow VPN interfaces
        for vpn_iface in [self.interface, self.backup_interface]:
            run_iptables(['-A', 'INPUT', '-i', vpn_iface, '-j', 'ACCEPT'])
            run_iptables(['-A', 'OUTPUT', '-o', vpn_iface, '-j', 'ACCEPT'])
        
        # Allow local network traffic if enabled
        if allow_lan and self.local_networks:
            for network in self.local_networks:
                run_iptables(['-A', 'INPUT', '-s', network, '-j', 'ACCEPT'])
                run_iptables(['-A', 'OUTPUT', '-d', network, '-j', 'ACCEPT'])
        
        # Allow DNS to specific servers
        for dns_server in self.allowed_dns:
            for proto in ['udp', 'tcp']:
                run_iptables([
                    '-A', 'OUTPUT', '-d', dns_server,
                    '-p', proto, '--dport', '53',
                    '-j', 'ACCEPT'
                ])
        
        # Allow VPN server connections
        for server in self.allowed_vpn_servers:
            run_iptables([
                '-A', 'OUTPUT', '-d', server['ip'],
                '-p', server['protocol'],
                '--dport', str(server['port']),
                '-j', 'ACCEPT'
            ])
        
        # Allow DHCP
        run_iptables(['-A', 'OUTPUT', '-p', 'udp', '--dport', '67:68', '-j', 'ACCEPT'])
        run_iptables(['-A', 'INPUT', '-p', 'udp', '--sport', '67:68', '-j', 'ACCEPT'])
        
        # Allow ICMP (ping) - limited
        run_iptables([
            '-A', 'OUTPUT', '-p', 'icmp', '--icmp-type', 'echo-request',
            '-m', 'limit', '--limit', '5/sec', '-j', 'ACCEPT'
        ])
        run_iptables([
            '-A', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-reply', '-j', 'ACCEPT'
        ])
        
        # Log dropped packets (for debugging)
        run_iptables([
            '-A', 'OUTPUT', '-m', 'limit', '--limit', '2/min',
            '-j', 'LOG', '--log-prefix', 'KS-DROP-OUT: ', '--log-level', '4'
        ])
        run_iptables([
            '-A', 'INPUT', '-m', 'limit', '--limit', '2/min',
            '-j', 'LOG', '--log-prefix', 'KS-DROP-IN: ', '--log-level', '4'
        ])
        
        # Block everything else
        run_iptables(['-P', 'INPUT', 'DROP'])
        run_iptables(['-P', 'FORWARD', 'DROP'])
        run_iptables(['-P', 'OUTPUT', 'DROP'])
    
    def _apply_ipv6_rules(self):
        """Apply IPv6 kill switch rules (block all IPv6)"""
        try:
            # Disable IPv6 at kernel level
            ipv6_settings = [
                '/proc/sys/net/ipv6/conf/all/disable_ipv6',
                '/proc/sys/net/ipv6/conf/default/disable_ipv6'
            ]
            
            for setting in ipv6_settings:
                try:
                    with open(setting, 'w') as f:
                        f.write('1')
                except IOError as e:
                    logger.warning(f"Could not disable IPv6 via {setting}: {e}")
        except Exception as e:
            logger.warning(f"Failed to disable IPv6: {e}")
        
        # Block all IPv6 traffic with ip6tables
        block6_cmds = [
            ['ip6tables', '-P', 'INPUT', 'DROP'],
            ['ip6tables', '-P', 'FORWARD', 'DROP'],
            ['ip6tables', '-P', 'OUTPUT', 'DROP'],
            ['ip6tables', '-F'],
            ['ip6tables', '-X'],
        ]
        
        for cmd in block6_cmds:
            try:
                subprocess.run(cmd, check=True, timeout=5)
            except subprocess.CalledProcessError:
                pass
    
    def _verify_rules(self) -> bool:
        """Verify that kill switch rules are applied correctly"""
        try:
            # Check that default policies are DROP
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            
            output = result.stdout.lower()
            
            # Verify DROP policies
            if 'policy drop' not in output:
                logger.error("Default DROP policy not found")
                return False
            
            # Verify VPN interface rules exist
            if self.interface.replace('+', '') not in output:
                logger.warning(f"VPN interface {self.interface} rules may not be present")
            
            logger.debug("Rule verification passed")
            return True
            
        except Exception as e:
            logger.error(f"Rule verification failed: {e}")
            return False
    
    def _save_state(self):
        """Save current kill switch state"""
        state = {
            'active': True,
            'timestamp': time.time(),
            'allowed_dns': list(self.allowed_dns),
            'allowed_vpn_servers': self.allowed_vpn_servers,
            'interface': self.interface,
            'backup_interface': self.backup_interface
        }
        
        state_file = Path('/tmp/vpn_killswitch_state.json')
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _cleanup_state(self):
        """Clean up state files"""
        for file_path in [Path('/tmp/vpn_killswitch_state.json'), self.backup_file]:
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
    
    def _emergency_recovery(self):
        """Emergency recovery if rules restoration fails"""
        logger.critical("Performing emergency recovery...")
        
        emergency_cmds = [
            ['iptables', '-P', 'INPUT', 'ACCEPT'],
            ['iptables', '-P', 'FORWARD', 'ACCEPT'],
            ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
            ['iptables', '-F'],
            ['iptables', '-X'],
            ['iptables', '-t', 'nat', '-F'],
            ['iptables', '-t', 'nat', '-X'],
            ['iptables', '-t', 'mangle', '-F'],
            ['iptables', '-t', 'mangle', '-X'],
            ['ip6tables', '-P', 'INPUT', 'ACCEPT'],
            ['ip6tables', '-P', 'FORWARD', 'ACCEPT'],
            ['ip6tables', '-P', 'OUTPUT', 'ACCEPT'],
            ['ip6tables', '-F'],
            ['ip6tables', '-X'],
        ]
        
        for cmd in emergency_cmds:
            try:
                subprocess.run(cmd, check=True, timeout=5)
            except Exception:
                pass
        
        # Re-enable IPv6
        try:
            for setting in ['/proc/sys/net/ipv6/conf/all/disable_ipv6',
                          '/proc/sys/net/ipv6/conf/default/disable_ipv6']:
                with open(setting, 'w') as f:
                    f.write('0')
        except Exception:
            pass
        
        logger.warning("Emergency recovery completed")
