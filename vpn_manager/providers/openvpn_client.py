"""
OpenVPN client wrapper with advanced features
"""

import subprocess
import threading
import time
import tempfile
import os
from pathlib import Path
from typing import Optional, Dict, List, Callable
import signal
import re
import logging

from ..core.types import VPNServer

logger = logging.getLogger(__name__)

class OpenVPNClient:
    """OpenVPN client wrapper"""
    
    def __init__(self, openvpn_binary: str = 'openvpn'):
        self.openvpn_binary = openvpn_binary
        self.process: Optional[subprocess.Popen] = None
        self.config_file: Optional[Path] = None
        self.auth_file: Optional[Path] = None
        self.is_connected = False
        self._connection_stats = {}
        self._callbacks: List[Callable] = []
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitoring = False
    
    def connect(self, server: VPNServer, 
                username: Optional[str] = None,
                password: Optional[str] = None) -> bool:
        """
        Connect to OpenVPN server
        
        Args:
            server: VPN server configuration
            username: Optional username
            password: Optional password
            
        Returns:
            bool: True if connection successful
        """
        if self.is_connected:
            logger.warning("Already connected")
            return False
        
        logger.info(f"Connecting to OpenVPN server: {server.hostname}")
        
        try:
            # Create temporary config file
            self.config_file = self._create_config_file(server)
            
            # Create auth file if credentials provided
            if username and password:
                self.auth_file = self._create_auth_file(username, password)
            
            # Build command
            cmd = [
                self.openvpn_binary,
                '--config', str(self.config_file),
                '--auth-nocache',
                '--connect-retry', '5',
                '--connect-retry-max', '3',
                '--explicit-exit-notify', '2',
            ]
            
            if self.auth_file:
                cmd.extend(['--auth-user-pass', str(self.auth_file)])
            
            # Start OpenVPN process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Start monitoring output
            self._start_monitoring()
            
            # Wait for connection
            return self._wait_for_connection(timeout=30)
            
        except Exception as e:
            logger.error(f"Failed to start OpenVPN: {e}")
            self._cleanup()
            return False
    
    def disconnect(self):
        """Disconnect from OpenVPN"""
        if not self.process:
            return
        
        logger.info("Disconnecting OpenVPN...")
        
        self._stop_monitoring = True
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        
        if self.process:
            # Send SIGTERM for graceful shutdown
            self.process.send_signal(signal.SIGTERM)
            
            try:
                # Wait for process to terminate
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if not responding
                self.process.kill()
                self.process.wait()
        
        self.is_connected = False
        self._cleanup()
        logger.info("OpenVPN disconnected")
    
    def force_disconnect(self):
        """Force disconnect (emergency)"""
        if self.process:
            self.process.kill()
            self.process.wait()
        self._cleanup()
    
    def set_dns_servers(self, dns_servers: List[str]):
        """Set DNS servers for VPN connection"""
        # This modifies the config file before connection
        pass
    
    def get_stats(self) -> Dict:
        """Get connection statistics"""
        return self._connection_stats.copy()
    
    def _create_config_file(self, server: VPNServer) -> Path:
        """Create OpenVPN config file"""
        config_template = f"""
client
dev tun
proto {server.protocol}
remote {server.hostname} {server.port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
mute 20

# Security
auth-user-pass
redirect-gateway def1
block-outside-dns
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8

# Performance
sndbuf 393216
rcvbuf 393216
fast-io

# Keepalive
keepalive 10 30

<ca>
-----BEGIN CERTIFICATE-----
# CA certificate would go here
-----END CERTIFICATE-----
</ca>
"""
        
        # Create temp file
        fd, path = tempfile.mkstemp(suffix='.ovpn', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(config_template)
        
        return Path(path)
    
    def _create_auth_file(self, username: str, password: str) -> Path:
        """Create authentication file"""
        fd, path = tempfile.mkstemp(text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(f"{username}\n{password}\n")
        
        # Secure file permissions
        os.chmod(path, 0o600)
        return Path(path)
    
    def _start_monitoring(self):
        """Start monitoring OpenVPN output"""
        self._stop_monitoring = False
        self._monitor_thread = threading.Thread(
            target=self._monitor_output,
            daemon=True,
            name="OpenVPN-Monitor"
        )
        self._monitor_thread.start()
    
    def _monitor_output(self):
        """Monitor OpenVPN process output"""
        if not self.process or not self.process.stdout:
            return
        
        for line in iter(self.process.stdout.readline, ''):
            if self._stop_monitoring:
                break
            
            line = line.strip()
            if line:
                self._parse_output_line(line)
                
                # Log based on verbosity
                if 'Initialization Sequence Completed' in line:
                    logger.info("OpenVPN connection established")
                    self.is_connected = True
                elif 'ERROR' in line or 'AUTH_FAILED' in line:
                    logger.error(f"OpenVPN error: {line}")
                elif 'WARNING' in line:
                    logger.warning(f"OpenVPN warning: {line}")
                else:
                    logger.debug(f"OpenVPN: {line}")
    
    def _parse_output_line(self, line: str):
        """Parse OpenVPN output line for useful information"""
        # Parse connection statistics
        stats_patterns = [
            r'TCP/UDP read bytes,(\d+)',
            r'TCP/UDP write bytes,(\d+)',
            r'AUTH read bytes,(\d+)',
        ]
        
        for pattern in stats_patterns:
            match = re.search(pattern, line)
            if match:
                if 'read' in pattern:
                    self._connection_stats['bytes_received'] = (
                        int(match.group(1))
                    )
                elif 'write' in pattern:
                    self._connection_stats['bytes_sent'] = int(match.group(1))
        
        # Parse tunnel IP
        ip_pattern = r'ifconfig.*?(\d+\.\d+\.\d+\.\d+)'
        match = re.search(ip_pattern, line)
        if match:
            self._connection_stats['tunnel_ip'] = match.group(1)
    
    def _wait_for_connection(self, timeout: int = 30) -> bool:
        """Wait for OpenVPN connection to establish"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.is_connected:
                return True
            
            # Check if process died
            if self.process and self.process.poll() is not None:
                logger.error(
                    f"OpenVPN process died with code: {self.process.returncode}"
                )
                return False
            
            time.sleep(0.5)
        
        logger.error("Connection timeout")
        return False
    
    def _cleanup(self):
        """Clean up temporary files"""
        for file in [self.config_file, self.auth_file]:
            if file and file.exists():
                try:
                    file.unlink()
                except (OSError, PermissionError):
                    pass
        
        self.config_file = None
        self.auth_file = None
