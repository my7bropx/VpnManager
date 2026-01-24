"""
Ip Rotator module
"""

import random
from typing import Optional, List
from .types import VPNServer
import logging

logger = logging.getLogger(__name__)


class IPRotator:
    """IP rotation functionality"""
    
    def __init__(self, servers: Optional[List[VPNServer]] = None):
        self.servers = servers or []
        self._server_cache = []
        self._cache_time = 0
        self.cache_duration = 300  # 5 minutes
    
    def get_random_server(self) -> Optional[VPNServer]:
        """Get a random server from the list"""
        if not self.servers:
            return None
        return random.choice(self.servers)
    
    def get_server_by_location(self, location: str) -> Optional[VPNServer]:
        """Get a server by location (country or city)"""
        matching_servers = [
            server for server in self.servers 
            if location.lower() in server.country.lower() or 
               location.lower() in server.city.lower()
        ]
        
        if not matching_servers:
            return None
            
        return random.choice(matching_servers)
    
    def get_best_server(
        self, exclude: Optional[str] = None
    ) -> Optional[VPNServer]:
        """Get the best available server based on score"""
        available_servers = self.servers
        
        if exclude:
            available_servers = [
                server for server in available_servers 
                if server.id != exclude
            ]
        
        if not available_servers:
            return None
        
        # Sort by score (higher is better), then latency (lower is better)
        best_server = min(
            available_servers,
            key=lambda s: (-s.score, s.latency or float('inf'))
        )
        
        return best_server
    
    def update_servers(self, servers: List[VPNServer]):
        """Update the server list"""
        self.servers = servers
        self._server_cache = []
        self._cache_time = 0
    
    def get_servers_by_country(self, country: str) -> List[VPNServer]:
        """Get all servers in a specific country"""
        return [
            server for server in self.servers 
            if server.country.lower() == country.lower()
        ]
    
    def get_all_servers(self) -> List[VPNServer]:
        """Get all available servers"""
        return self.servers.copy()
    
    def find_servers(
        self, country: Optional[str] = None,
        protocol: Optional[str] = None
    ) -> List[VPNServer]:
        """Find servers matching criteria"""
        filtered_servers = self.servers
        
        if country:
            filtered_servers = [
                s for s in filtered_servers 
                if country.lower() in s.country.lower()
            ]
        
        if protocol:
            filtered_servers = [
                s for s in filtered_servers 
                if s.protocol.lower() == protocol.lower()
            ]
        
        return filtered_servers
