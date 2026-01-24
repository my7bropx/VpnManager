"""
Wireguard Client module
"""

import subprocess
import logging
import os
from pathlib import Path
from typing import Optional, Dict, List
from ..core.types import VPNServer

logger = logging.getLogger(__name__)

class WireGuardClient:
    """WireGuard client wrapper using wg-quick"""
    
    def __init__(self):
        self.config_path: Optional[str] = None
        self.is_connected = False
        self._connection_stats = {}

    def connect(self, server: VPNServer, 
                username: Optional[str] = None,
                password: Optional[str] = None) -> bool:
        """
        Connect to WireGuard server
        
        Args:
            server: VPN server configuration (must have config_path)
            
        Returns:
            bool: True if connection successful
        """
        logger.info(f"Connecting to WireGuard server: {server.hostname}")
        
        if not server.config_path:
            logger.error("No config path provided for WireGuard connection")
            return False

        self.config_path = server.config_path

        try:
            # Use wg-quick to bring up the interface
            cmd = ['wg-quick', 'up', self.config_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            logger.info(f"WireGuard connection established using {self.config_path}")
            self.is_connected = True
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"WireGuard connection failed: {e.stderr}")
            self.is_connected = False
            return False
        except Exception as e:
            logger.error(f"WireGuard error: {e}")
            self.is_connected = False
            return False

    def disconnect(self):
        """Disconnect from WireGuard"""
        if not self.config_path or not self.is_connected:
            return

        logger.info("Disconnecting WireGuard...")
        try:
            cmd = ['wg-quick', 'down', self.config_path]
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info("WireGuard disconnected")
        except Exception as e:
            logger.error(f"Failed to disconnect WireGuard: {e}")
        finally:
            self.is_connected = False
            self.config_path = None

    def force_disconnect(self):
        """Force disconnect (wrapper for disconnect as wg-quick handles cleanup)"""
        self.disconnect()

    def get_stats(self) -> Dict:
        """Get connection statistics from wg show"""
        stats = {'bytes_sent': 0, 'bytes_received': 0}
        
        try:
            # Parse 'wg show' output for transfer stats
            # Output format example: interface: <iface> ... transfer: <rx> received, <tx> sent
            result = subprocess.run(['wg', 'show', 'all', 'transfer'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.strip().split()
                if len(parts) >= 3:
                    stats['bytes_received'] = int(parts[1])
                    stats['bytes_sent'] = int(parts[2])
        except Exception as e:
            logger.debug(f"Failed to get WireGuard stats: {e}")
            
        return stats
        
    def set_dns_servers(self, dns_servers: List[str]):
        """
        Set DNS servers. 
        Note: For WireGuard, DNS is usually set in the config file.
        This method is a placeholder if we want to modify the config dynamically.
        """
        pass
