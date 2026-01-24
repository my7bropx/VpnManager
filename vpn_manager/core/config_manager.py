"""
Configuration Manager for VPN profiles and settings
"""

import json
import yaml
from pathlib import Path
from typing import Optional, Dict, List, Any
import logging
from dataclasses import asdict

from .types import VPNServer

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manage VPN configuration files and profiles"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration manager
        
        Args:
            config_dir: Directory for configuration files
        """
        if config_dir is None:
            self.config_dir = Path.home() / '.config' / 'vpn-manager'
        else:
            self.config_dir = Path(config_dir)
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration file paths
        self.settings_file = self.config_dir / 'settings.yaml'
        self.locations_file = self.config_dir / 'locations.json'
        self.profiles_dir = self.config_dir / 'profiles'
        self.profiles_dir.mkdir(exist_ok=True)
        
        # Default settings
        self.default_settings = {
            'debug': False,
            'log_level': 'INFO',
            'log_file': str(self.config_dir / 'logs' / 'vpn_manager.log'),
            'default_protocol': 'udp',
            'auto_reconnect': True,
            'reconnect_interval': 30,
            'connection_timeout': 60,
            'kill_switch': {
                'enabled': True,
                'strict_mode': False,
                'allow_lan': True,
                'allowed_interfaces': ['lo', 'docker0']
            },
            'ip_rotation': {
                'enabled': False,
                'interval': 3600,
                'random_location': True
            },
            'dns': {
                'leak_protection': True,
                'custom_servers': ['1.1.1.1', '8.8.8.8']
            },
            'monitoring': {
                'enabled': True,
                'check_interval': 30,
                'health_check_url': 'https://httpbin.org/ip'
            }
        }
        
        # Load or create settings
        self.settings = self.load_settings()
    
    def load_settings(self) -> Dict:
        """Load settings from file or create default"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    settings = yaml.safe_load(f)
                
                # Merge with defaults to ensure all keys exist
                merged = self._deep_merge(self.default_settings.copy(), settings)
                logger.debug("Settings loaded successfully")
                return merged
                
            except Exception as e:
                logger.error(f"Failed to load settings: {e}")
                logger.info("Using default settings")
                return self.default_settings.copy()
        else:
            # Create default settings file
            self.save_settings(self.default_settings)
            return self.default_settings.copy()
    
    def save_settings(self, settings: Optional[Dict] = None):
        """Save settings to file"""
        if settings is None:
            settings = self.settings
        
        try:
            with open(self.settings_file, 'w') as f:
                yaml.dump(settings, f, default_flow_style=False, sort_keys=False)
            
            self.settings = settings
            logger.debug("Settings saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get setting value using dot notation
        
        Args:
            key: Setting key (e.g., 'kill_switch.enabled')
            default: Default value if key not found
        """
        keys = key.split('.')
        value = self.settings
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set setting value using dot notation
        
        Args:
            key: Setting key (e.g., 'kill_switch.enabled')
            value: Value to set
        """
        keys = key.split('.')
        settings = self.settings
        
        for k in keys[:-1]:
            if k not in settings:
                settings[k] = {}
            settings = settings[k]
        
        settings[keys[-1]] = value
        self.save_settings()
    
    def load_locations(self) -> Dict:
        """Load server locations from file"""
        if self.locations_file.exists():
            try:
                with open(self.locations_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load locations: {e}")
                return {'locations': {}}
        
        return {'locations': {}}
    
    def save_locations(self, locations: Dict):
        """Save server locations to file"""
        try:
            with open(self.locations_file, 'w') as f:
                json.dump(locations, f, indent=2)
            logger.debug("Locations saved successfully")
        except Exception as e:
            logger.error(f"Failed to save locations: {e}")
    
    def load_ovpn_profile(self, profile_path: Path) -> Dict:
        """
        Load and parse OpenVPN profile
        
        Args:
            profile_path: Path to .ovpn file
            
        Returns:
            Dict containing parsed profile data
        """
        if not profile_path.exists():
            raise FileNotFoundError(f"Profile not found: {profile_path}")
        
        profile_data = {
            'name': profile_path.stem,
            'path': str(profile_path),
            'protocol': 'udp',
            'port': 1194,
            'remote': None,
            'ca': None,
            'cert': None,
            'key': None,
            'auth_user_pass': False,
            'dns_servers': [],
            'extra_options': {}
        }
        
        try:
            with open(profile_path, 'r') as f:
                content = f.read()
            
            in_cert_block = False
            cert_block_type = None
            cert_content = []
            
            for line in content.split('\n'):
                line = line.strip()
                
                # Handle certificate blocks
                if line.startswith('<ca>'):
                    in_cert_block = True
                    cert_block_type = 'ca'
                    cert_content = []
                    continue
                elif line.startswith('</ca>'):
                    in_cert_block = False
                    profile_data['ca'] = '\n'.join(cert_content)
                    continue
                elif line.startswith('<cert>'):
                    in_cert_block = True
                    cert_block_type = 'cert'
                    cert_content = []
                    continue
                elif line.startswith('</cert>'):
                    in_cert_block = False
                    profile_data['cert'] = '\n'.join(cert_content)
                    continue
                elif line.startswith('<key>'):
                    in_cert_block = True
                    cert_block_type = 'key'
                    cert_content = []
                    continue
                elif line.startswith('</key>'):
                    in_cert_block = False
                    profile_data['key'] = '\n'.join(cert_content)
                    continue
                
                if in_cert_block:
                    cert_content.append(line)
                    continue
                
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                
                # Parse configuration options
                parts = line.split(None, 1)
                if not parts:
                    continue
                
                option = parts[0].lower()
                value = parts[1] if len(parts) > 1 else None
                
                if option == 'remote':
                    remote_parts = value.split()
                    profile_data['remote'] = remote_parts[0]
                    if len(remote_parts) > 1:
                        profile_data['port'] = int(remote_parts[1])
                    if len(remote_parts) > 2:
                        profile_data['protocol'] = remote_parts[2]
                
                elif option == 'proto':
                    profile_data['protocol'] = value.lower()
                
                elif option == 'port':
                    profile_data['port'] = int(value)
                
                elif option == 'auth-user-pass':
                    profile_data['auth_user_pass'] = True
                
                elif option == 'dhcp-option':
                    dhcp_parts = value.split(None, 1)
                    if dhcp_parts[0] == 'DNS':
                        profile_data['dns_servers'].append(dhcp_parts[1])
                
                elif option in ['ca', 'cert', 'key', 'tls-auth', 'tls-crypt']:
                    if value:
                        profile_data[option.replace('-', '_')] = value
                
                else:
                    # Store other options
                    profile_data['extra_options'][option] = value
            
            logger.debug(f"Loaded profile: {profile_path.name}")
            return profile_data
            
        except Exception as e:
            logger.error(f"Failed to parse profile {profile_path}: {e}")
            raise
    
    def save_ovpn_profile(self, profile_data: Dict, output_path: Optional[Path] = None) -> Path:
        """
        Save OpenVPN profile to file
        
        Args:
            profile_data: Profile configuration
            output_path: Output file path (optional)
            
        Returns:
            Path to saved profile
        """
        if output_path is None:
            output_path = self.profiles_dir / f"{profile_data['name']}.ovpn"
        
        try:
            with open(output_path, 'w') as f:
                f.write(f"# OpenVPN Profile: {profile_data['name']}\n")
                f.write(f"# Generated by VPN Manager\n\n")
                
                # Basic options
                f.write("client\n")
                f.write("dev tun\n")
                f.write(f"proto {profile_data['protocol']}\n")
                
                # Remote server
                if profile_data.get('remote'):
                    f.write(f"remote {profile_data['remote']} {profile_data['port']}\n")
                
                # Standard options
                f.write("resolv-retry infinite\n")
                f.write("nobind\n")
                f.write("persist-key\n")
                f.write("persist-tun\n")
                f.write("remote-cert-tls server\n")
                
                # Cipher and auth
                f.write("cipher AES-256-GCM\n")
                f.write("auth SHA256\n")
                
                # Logging
                f.write("verb 3\n")
                f.write("mute 20\n\n")
                
                # Authentication
                if profile_data.get('auth_user_pass'):
                    f.write("auth-user-pass\n")
                
                # DNS servers
                for dns in profile_data.get('dns_servers', []):
                    f.write(f"dhcp-option DNS {dns}\n")
                
                # Extra options
                for option, value in profile_data.get('extra_options', {}).items():
                    if value:
                        f.write(f"{option} {value}\n")
                    else:
                        f.write(f"{option}\n")
                
                # Certificate blocks
                if profile_data.get('ca'):
                    f.write("\n<ca>\n")
                    f.write(profile_data['ca'])
                    f.write("\n</ca>\n")
                
                if profile_data.get('cert'):
                    f.write("\n<cert>\n")
                    f.write(profile_data['cert'])
                    f.write("\n</cert>\n")
                
                if profile_data.get('key'):
                    f.write("\n<key>\n")
                    f.write(profile_data['key'])
                    f.write("\n</key>\n")
            
            logger.info(f"Profile saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to save profile: {e}")
            raise
    
    def list_profiles(self) -> List[Dict]:
        """List all available VPN profiles"""
        profiles = []
        
        for profile_file in self.profiles_dir.glob('*.ovpn'):
            try:
                profile_data = self.load_ovpn_profile(profile_file)
                profiles.append({
                    'name': profile_data['name'],
                    'path': str(profile_file),
                    'protocol': profile_data['protocol'],
                    'port': profile_data['port'],
                    'remote': profile_data.get('remote', 'Unknown')
                })
            except Exception as e:
                logger.warning(f"Failed to load profile {profile_file}: {e}")
        
        return profiles
    
    def create_server_from_profile(self, profile_path: Path, server_id: Optional[str] = None) -> VPNServer:
        """
        Create VPNServer object from profile
        
        Args:
            profile_path: Path to .ovpn profile
            server_id: Optional server ID
            
        Returns:
            VPNServer object
        """
        profile = self.load_ovpn_profile(profile_path)
        
        if server_id is None:
            server_id = profile['name']
        
        return VPNServer(
            id=server_id,
            hostname=profile.get('remote', 'unknown'),
            ip_address=profile.get('remote', '0.0.0.0'),
            country='Unknown',
            city='Unknown',
            isp='Unknown',
            protocol=profile['protocol'],
            port=profile['port'],
            score=1.0
        )
    
    def export_settings(self, output_path: Path):
        """Export all settings to a single file"""
        export_data = {
            'settings': self.settings,
            'locations': self.load_locations(),
            'profiles': self.list_profiles()
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Settings exported to: {output_path}")
    
    def import_settings(self, input_path: Path):
        """Import settings from a file"""
        with open(input_path, 'r') as f:
            import_data = json.load(f)
        
        if 'settings' in import_data:
            self.save_settings(import_data['settings'])
        
        if 'locations' in import_data:
            self.save_locations(import_data['locations'])
        
        logger.info(f"Settings imported from: {input_path}")
    
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

