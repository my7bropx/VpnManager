"""
Network utilities for VPN management
"""

import socket
import subprocess
import json
import sys
import time
import logging
from typing import Optional, List, Dict, Tuple
import urllib.request
import urllib.error
import ipaddress
import threading
import queue

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    dns = None

logger = logging.getLogger(__name__)

class NetworkTools:
    """Network diagnostic and utility tools"""
    
    def __init__(self):
        self.timeout = 5
        self._public_ip_cache = None
        self._cache_time = 0
        self.cache_duration = 300  # 5 minutes
    
    def get_public_ip(self, force_refresh: bool = False) -> Optional[str]:
        """Get current public IP address"""
        current_time = time.time()
        
        if (not force_refresh and self._public_ip_cache and 
            current_time - self._cache_time < self.cache_duration):
            return self._public_ip_cache
        
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://checkip.amazonaws.com',
            'https://ifconfig.me/ip',
        ]
        
        for service in services:
            try:
                with urllib.request.urlopen(
                    service, timeout=self.timeout
                ) as response:
                    ip = response.read().decode('utf-8').strip()
                    
                    # Validate IP address
                    if self._is_valid_ip(ip):
                        self._public_ip_cache = ip
                        self._cache_time = current_time
                        return ip
                        
            except (urllib.error.URLError, socket.timeout):
                continue
        
        return None
    
    def get_geo_location(self, ip_address: str) -> Dict:
        """Get geographical location for IP address"""
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'location': (
                        f"{data.get('city', '')}, {data.get('country', '')}"
                    )
                }
        except (urllib.error.URLError, json.JSONDecodeError, OSError, TimeoutError):
            return {'location': 'Unknown'}
    
    def check_dns_leak(self, expected_dns: List[str]) -> List[str]:
        """
        Check for DNS leaks
        
        Args:
            expected_dns: List of expected DNS servers
            
        Returns:
            List of unexpected DNS servers found
        """
        if not DNS_AVAILABLE:
            # Fallback: use basic socket operations
            logger.warning("DNS leak detection limited - dnspython not available")
            return []
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        # Test domains for DNS resolution
        test_domains = [
            'whoami.akamai.net',
            'myip.opendns.com',
            'ident.me',
        ]
        
        found_servers = set()
        
        for domain in test_domains:
            try:
                # Get nameservers for domain
                answers = resolver.resolve(domain, 'A')
                for answer in answers:
                    # Reverse lookup to find DNS server
                    try:
                        reversed_dns = socket.gethostbyaddr(str(answer))[0]
                        found_servers.add(reversed_dns)
                    except socket.herror:
                        found_servers.add(str(answer))
            except Exception as e:
                # Handle DNS exceptions when dnspython is available
                if DNS_AVAILABLE and dns:
                    if isinstance(e, (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                                    dns.resolver.Timeout)):
                        continue
                # For other exceptions or when dnspython is not available
                continue
        
        # Check which servers are not in expected list
        leaks = []
        for server in found_servers:
            # Check if server matches any expected DNS
            is_expected = False
            for expected in expected_dns:
                if expected in server or server in expected:
                    is_expected = True
                    break
            
            if not is_expected:
                leaks.append(server)
        
        return leaks
    
    def test_latency(self, host: str, port: int = 80, 
                    samples: int = 3) -> Optional[float]:
        """Test latency to host"""
        latencies = []
        
        for _ in range(samples):
            try:
                start = time.perf_counter()
                sock = socket.create_connection((host, port), timeout=self.timeout)
                sock.close()
                latency = (time.perf_counter() - start) * 1000  # Convert to ms
                latencies.append(latency)
            except (socket.timeout, socket.error):
                continue
        
        if latencies:
            return sum(latencies) / len(latencies)
        
        return None
    
    def get_default_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            # Linux/MacOS
            if sys.platform in ['linux', 'darwin']:
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'default via' in line:
                        parts = line.split()
                        return parts[2]
            
            # Windows
            elif sys.platform == 'win32':
                result = subprocess.run(
                    ['route', 'print', '0.0.0.0'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        if len(parts) > 2:
                            return parts[2]
        
        except (subprocess.CalledProcessError, IndexError):
            pass
        
        return None
    
    def get_network_interfaces(self) -> List[str]:
        """Get list of network interfaces"""
        interfaces = []
        
        try:
            if sys.platform in ['linux', 'darwin']:
                result = subprocess.run(
                    ['ip', 'link', 'show'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line and not 'lo:' in line:
                        parts = line.split(':')
                        if len(parts) > 1 and parts[1].strip():
                            interfaces.append(parts[1].strip())
            
            elif sys.platform == 'win32':
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Connected' in line or 'Disconnected' in line:
                        parts = line.split()
                        if len(parts) > 3:
                            interfaces.append(parts[-1])
        
        except subprocess.CalledProcessError:
            pass
        
        return interfaces
    
    def get_current_dns(self) -> List[str]:
        """Get current DNS servers"""
        dns_servers = []
        
        try:
            if sys.platform in ['linux', 'darwin']:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            
            elif sys.platform == 'win32':
                result = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'DNS Servers' in line:
                        dns = line.split(':')[-1].strip()
                        if dns:
                            dns_servers.append(dns)
                        
                        # Check next lines for additional DNS servers
                        j = i + 1
                        while j < len(lines) and lines[j].strip().startswith('.'):
                            dns_servers.append(lines[j].strip())
                            j += 1
        
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        
        return dns_servers
    
    def is_port_open(self, host: str, port: int, 
                    protocol: str = 'tcp') -> bool:
        """Check if port is open on host"""
        try:
            if protocol.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            elif protocol.lower() == 'udp':
                # UDP is connectionless, so we try to send empty packet
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b'', (host, port))
                sock.recvfrom(1024)  # Try to receive response
                sock.close()
                return True
        except (socket.timeout, socket.error):
            return False
        
        return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def run_traceroute(self, host: str, max_hops: int = 30) -> List[Dict]:
        """Run traceroute to host"""
        hops = []
        
        try:
            if sys.platform in ['linux', 'darwin']:
                cmd = ['traceroute', '-m', str(max_hops), '-n', host]
            elif sys.platform == 'win32':
                cmd = ['tracert', '-h', str(max_hops), '-d', host]
            else:
                return hops
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    hops.append({'hop': line.strip()})
            
        except subprocess.CalledProcessError:
            pass
        
        return hops
