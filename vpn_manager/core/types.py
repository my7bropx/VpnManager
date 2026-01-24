"""
Type definitions for VPN manager
"""

from dataclasses import dataclass
from typing import Optional, List, Dict


@dataclass
class VPNServer:
    """VPN server information"""
    id: str
    hostname: str
    ip_address: str
    country: str
    city: str
    isp: str
    protocol: str  # udp/tcp
    port: int
    latency: Optional[float] = None
    load: Optional[int] = None
    score: float = 0.0
    config_path: Optional[str] = None
    
    @classmethod
    def from_config(cls, config: Dict) -> 'VPNServer':
        return cls(**config)


@dataclass
class ConnectionStats:
    """Connection statistics"""
    bytes_sent: int = 0
    bytes_received: int = 0
    connected_since: Optional[float] = None
    session_duration: float = 0.0
    ip_address: Optional[str] = None
    location: Optional[str] = None
    server_id: Optional[str] = None
    dns_servers: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []
