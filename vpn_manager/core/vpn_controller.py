"""
Main VPN controller with state management and failover
"""

import threading
import time
import json
from dataclasses import asdict
from typing import Optional, Dict, List, Callable
from enum import Enum, auto
from pathlib import Path

from ..providers.openvpn_client import OpenVPNClient
from ..providers.wireguard_client import WireGuardClient
from .kill_switch import KillSwitch
from .ip_rotator import IPRotator
from .types import VPNServer, ConnectionStats
from ..utils.network_tools import NetworkTools
from ..utils.logging_setup import get_logger

logger = get_logger(__name__)

class VPNState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    ERROR = auto()
    ROTATING = auto()

class VPNController:
    """Main VPN controller with state management"""
    
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.state = VPNState.DISCONNECTED
        self.stats = ConnectionStats()
        self.current_server: Optional[VPNServer] = None
        self.vpn_client: Optional[OpenVPNClient] = None # Type hint can be Union in future
        self.kill_switch: Optional[KillSwitch] = None
        self.ip_rotator: Optional[IPRotator] = None
        self.network_tools = NetworkTools()
        
        # Threading
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_running = False
        self._connection_lock = threading.Lock()
        self._callbacks: Dict[str, List[Callable]] = {
            'state_change': [],
            'ip_change': [],
            'error': []
        }
        
        # Configuration
        self.config_dir = Path.home() / '.config' / 'vpn-manager'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self._load_config()
        self._initialized = True
    
    def _load_config(self):
        """Load configuration"""
        config_file = self.config_dir / 'config.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                'default_protocol': 'udp',
                'default_port': 1194,
                'kill_switch_enabled': True,
                'auto_reconnect': True,
                'dns_servers': ['1.1.1.1', '8.8.8.8'],
                'server_list_url': 'https://api.example.com/vpn/servers',
                'check_interval': 30,
                'max_reconnect_attempts': 3
            }
            self._save_config()
    
    def _save_config(self):
        """Save configuration"""
        config_file = self.config_dir / 'config.json'
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def register_callback(self, event: str, callback: Callable):
        """Register event callback"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _notify_callbacks(self, event: str, *args, **kwargs):
        """Notify registered callbacks"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def connect(self, server: VPNServer, enable_kill_switch: bool = True,
                dns_servers: Optional[List[str]] = None) -> bool:
        """
        Connect to VPN server
        
        Args:
            server: VPN server to connect to
            enable_kill_switch: Enable kill switch
            dns_servers: Custom DNS servers
            
        Returns:
            bool: True if connection successful
        """
        with self._connection_lock:
            if self.state in [VPNState.CONNECTING, VPNState.CONNECTED]:
                logger.warning("Already connected or connecting")
                return False
            
            logger.info(f"Connecting to {server.country}/{server.city} "
                       f"({server.hostname})")
            
            self._change_state(VPNState.CONNECTING)
            
            try:
                # Initialize kill switch if enabled
                if enable_kill_switch:
                    self.kill_switch = KillSwitch()
                    self.kill_switch.enable()
                
                # Initialize VPN client based on protocol
                if server.protocol.lower() == 'wireguard':
                    self.vpn_client = WireGuardClient()
                else:
                    self.vpn_client = OpenVPNClient()
                
                # Configure DNS if provided
                if dns_servers and hasattr(self.vpn_client, 'set_dns_servers'):
                    self.vpn_client.set_dns_servers(dns_servers)
                
                # Connect to server
                if not self.vpn_client.connect(server):
                    raise ConnectionError(
                        f"Failed to connect to {server.hostname}"
                    )
                
                # Update connection stats
                self.current_server = server
                self.stats.connected_since = time.time()
                self.stats.server_id = server.id
                self.stats.dns_servers = (
                    dns_servers or self.config['dns_servers']
                )
                
                # Get connection info
                self._update_connection_info()
                
                # Start monitoring thread
                self._start_monitoring()
                
                self._change_state(VPNState.CONNECTED)
                logger.info(
                    f"Connected successfully. IP: {self.stats.ip_address}"
                )
                
                # Notify IP change
                self._notify_callbacks('ip_change', self.stats.ip_address)
                
                return True
                
            except Exception as e:
                logger.error(f"Connection failed: {e}")
                self._cleanup_resources()
                self._change_state(VPNState.ERROR, str(e))
                return False
    
    def disconnect(self, keep_kill_switch: bool = False) -> bool:
        """
        Disconnect from VPN
        
        Args:
            keep_kill_switch: Keep kill switch active
            
        Returns:
            bool: True if disconnection successful
        """
        with self._connection_lock:
            if self.state == VPNState.DISCONNECTED:
                return True
            
            logger.info("Disconnecting VPN...")
            self._change_state(VPNState.DISCONNECTING)
            
            try:
                # Stop monitoring
                self._stop_monitoring()
                
                # Disconnect VPN client
                if self.vpn_client:
                    self.vpn_client.disconnect()
                
                # Disable kill switch unless requested to keep
                if self.kill_switch and not keep_kill_switch:
                    self.kill_switch.disable()
                
                # Reset state
                self._cleanup_resources()
                
                self._change_state(VPNState.DISCONNECTED)
                logger.info("Disconnected successfully")
                
                return True
                
            except Exception as e:
                logger.error(f"Disconnection failed: {e}")
                self._change_state(VPNState.ERROR, str(e))
                return False
    
    def rotate_ip(self, new_location: Optional[str] = None, 
                  random_location: bool = False) -> bool:
        """
        Rotate IP address by reconnecting
        
        Args:
            new_location: Specific location to rotate to
            random_location: Choose random location
            
        Returns:
            bool: True if rotation successful
        """
        if self.state != VPNState.CONNECTED:
            logger.error("Cannot rotate: Not connected")
            return False
        
        logger.info("Rotating IP address...")
        self._change_state(VPNState.ROTATING)
        
        old_ip = self.stats.ip_address
        
        try:
            # Get new server
            if self.ip_rotator is None:
                self.ip_rotator = IPRotator()
            
            if random_location:
                new_server = self.ip_rotator.get_random_server()
            elif new_location:
                new_server = self.ip_rotator.get_server_by_location(
                    new_location
                )
            else:
                new_server = self.ip_rotator.get_best_server(
                    exclude=self.current_server.id 
                    if self.current_server else None
                )
            
            if not new_server:
                raise ValueError("No suitable server found")
            
            # Temporarily disable kill switch for smooth transition
            kill_switch_active = (
                self.kill_switch and self.kill_switch.is_active()
            )
            if kill_switch_active and self.kill_switch:
                self.kill_switch.disable()
            
            # Disconnect from current server
            if self.vpn_client:
                self.vpn_client.disconnect()
            
            # Connect to new server
            dns_servers = self.stats.dns_servers
            success = self.connect(
                server=new_server,
                enable_kill_switch=kill_switch_active or False,
                dns_servers=dns_servers
            )
            
            if success:
                logger.info(f"IP rotated: {old_ip} -> {self.stats.ip_address}")
                self._notify_callbacks('ip_change', self.stats.ip_address)
                return True
            else:
                # Try to reconnect to old server
                if self.current_server:
                    logger.warning(
                        "Rotation failed, attempting to reconnect to previous server"
                    )
                    self.connect(
                        server=self.current_server,
                        enable_kill_switch=kill_switch_active or False,
                        dns_servers=dns_servers
                    )
                return False
                
        except Exception as e:
            logger.error(f"IP rotation failed: {e}")
            self._change_state(VPNState.ERROR, str(e))
            return False
    
    def emergency_disconnect(self):
        """Emergency disconnect - bypass normal procedures"""
        logger.critical("Emergency disconnect triggered")
        
        # Stop monitoring immediately
        self._monitor_running = False
        
        # Kill VPN process
        if self.vpn_client:
            try:
                self.vpn_client.force_disconnect()
            except (ConnectionError, OSError, Exception):
                pass
        
        # Disable kill switch
        if self.kill_switch:
            try:
                self.kill_switch.disable()
            except (OSError, Exception):
                pass
        
        self._change_state(VPNState.DISCONNECTED)
    
    def _update_connection_info(self):
        """Update connection information"""
        if not self.vpn_client:
            return
        
        # Get public IP
        self.stats.ip_address = self.network_tools.get_public_ip()
        
        # Get location info
        if self.stats.ip_address:
            geo_info = self.network_tools.get_geo_location(
                self.stats.ip_address
            )
            self.stats.location = geo_info.get('location', 'Unknown')
        
        # Get connection stats from VPN client
        stats = self.vpn_client.get_stats()
        if stats:
            self.stats.bytes_sent = stats.get('bytes_sent', 0)
            self.stats.bytes_received = stats.get('bytes_received', 0)
    
    def _start_monitoring(self):
        """Start connection monitoring thread"""
        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_connection,
            daemon=True,
            name="VPN-Monitor"
        )
        self._monitor_thread.start()
    
    def _stop_monitoring(self):
        """Stop connection monitoring"""
        self._monitor_running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
    
    def _monitor_connection(self):
        """Monitor VPN connection status"""
        check_interval = self.config.get('check_interval', 30)
        consecutive_failures = 0
        max_failures = 3
        
        while self._monitor_running:
            try:
                time.sleep(check_interval)
                
                if not self._monitor_running:
                    break
                
                # Check VPN connection
                if (self.vpn_client and 
                    hasattr(self.vpn_client, 'is_connected') and 
                    self.vpn_client.is_connected):
                    # Update stats
                    self._update_connection_info()
                    
                    # Check for IP leak
                    if self.config.get('check_for_leaks', True):
                        if self._check_for_leaks():
                            logger.warning("Potential leak detected!")
                            self._handle_leak()
                    
                    consecutive_failures = 0
                    
                else:
                    # Connection lost
                    consecutive_failures += 1
                    logger.warning(
                        f"Connection check failed ({consecutive_failures}/{max_failures})"
                    )
                    
                    if consecutive_failures >= max_failures:
                        logger.error(
                            "Connection lost, attempting reconnect..."
                        )
                        
                        if self.config.get('auto_reconnect', True):
                            self._attempt_reconnect()
                        else:
                            self._change_state(
                                VPNState.ERROR, "Connection lost"
                            )
                            break
                
                # Update session duration
                if self.stats.connected_since:
                    self.stats.session_duration = (
                        time.time() - self.stats.connected_since
                    )
                    
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)  # Prevent tight loop on error
    
    def _check_for_leaks(self) -> bool:
        """Check for IP/DNS leaks"""
        if not self.kill_switch or not self.kill_switch.is_active():
            return False
        
        # Check public IP matches VPN IP
        current_ip = self.network_tools.get_public_ip()
        if current_ip and self.stats.ip_address:
            if current_ip != self.stats.ip_address:
                logger.warning(
                    f"IP mismatch: VPN={self.stats.ip_address}, Current={current_ip}"
                )
                return True
        
        # Check DNS leaks
        dns_leak = self.network_tools.check_dns_leak(
            self.stats.dns_servers or []
        )
        if dns_leak:
            logger.warning("DNS leak detected!")
            return True
        
        return False
    
    def _handle_leak(self):
        """Handle detected leak"""
        logger.critical("Leak detected! Enforcing kill switch...")
        
        if self.kill_switch:
            self.kill_switch.enable(force=True)
        
        # Attempt to reconnect
        self._attempt_reconnect()
    
    def _attempt_reconnect(self):
        """Attempt to reconnect to VPN"""
        max_attempts = self.config.get('max_reconnect_attempts', 3)
        
        for attempt in range(max_attempts):
            try:
                logger.info(
                    f"Reconnection attempt {attempt + 1}/{max_attempts}"
                )
                
                # Get best available server
                if self.ip_rotator is None:
                    self.ip_rotator = IPRotator()
                
                new_server = self.ip_rotator.get_best_server(
                    exclude=self.current_server.id if self.current_server else None
                )
                
                if new_server and self.connect(
                    server=new_server,
                    enable_kill_switch=True,
                    dns_servers=self.stats.dns_servers
                ):
                    logger.info("Reconnected successfully")
                    return
                
            except Exception as e:
                logger.error(f"Reconnect attempt {attempt + 1} failed: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        logger.error("All reconnection attempts failed")
        self.emergency_disconnect()
    
    def _cleanup_resources(self):
        """Clean up resources"""
        self.current_server = None
        self.stats = ConnectionStats()
        
        if self.vpn_client:
            self.vpn_client = None
        
        # Don't clean kill_switch if it should remain active
    
    def _change_state(self, new_state: VPNState, message: str = ""):
        """Change VPN state with notification"""
        old_state = self.state
        self.state = new_state
        
        logger.debug(f"State change: {old_state.name} -> {new_state.name} {message}")
        self._notify_callbacks('state_change', old_state, new_state, message)
    
    def get_status(self) -> Dict:
        """Get current VPN status"""
        return {
            'state': self.state.name,
            'connected': self.state == VPNState.CONNECTED,
            'server': asdict(self.current_server) if self.current_server else None,
            'statistics': asdict(self.stats),
            'kill_switch_active': self.kill_switch.is_active() if self.kill_switch else False,
            'uptime': self.stats.session_duration if self.stats.connected_since else 0
        }
