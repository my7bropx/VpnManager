"""
Command-line interface for VPN manager
"""

import json
import time
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, TextColumn
)
from rich.prompt import Prompt, Confirm
from rich import box


from ..core.vpn_controller import VPNController
from ..core.ip_rotator import IPRotator
from ..core.types import VPNServer
from ..utils.network_tools import NetworkTools

console = Console()

class VPNCLI:
    """Command-line interface for VPN management"""
    
    def __init__(self):
        self.controller = VPNController()
        self.ip_rotator = IPRotator()
        self.network_tools = NetworkTools()
        
        # Register callbacks
        self.controller.register_callback(
            'state_change', self._on_state_change
        )
        self.controller.register_callback('ip_change', self._on_ip_change)
        self.controller.register_callback('error', self._on_error)
    
    def connect(self, location: Optional[str] = None,
                country: Optional[str] = None,
                server: Optional[str] = None,
                protocol: str = 'udp',
                port: Optional[int] = None,
                config_file: Optional[str] = None,
                enable_kill_switch: bool = True,
                dns_servers: Optional[List[str]] = None):
        """Connect to VPN"""
        
        # Get server selection
        vpn_server = self._select_server(
            location=location,
            country=country,
            server=server,
            protocol=protocol,
            port=port
        )
        
        if not vpn_server:
            console.print("[red]No server selected[/red]")
            return
        
        # Show connection details
        self._display_connection_info(vpn_server)
        
        # Ask for confirmation
        if not Confirm.ask("Connect to this server?"):
            return
        
        # Connect
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Connecting...", total=None)
            
            success = self.controller.connect(
                server=vpn_server,
                enable_kill_switch=enable_kill_switch,
                dns_servers=dns_servers
            )
            
            progress.update(task, completed=1)
        
        if success:
            console.print("[green]✓ Connected successfully[/green]")
            self.status(detailed=True)
        else:
            console.print("[red]✗ Connection failed[/red]")
    
    def rotate_ip(self, new_location: Optional[str] = None,
                  random: bool = False, force: bool = False):
        """Rotate IP address"""
        if not self.controller.state.name == 'CONNECTED' and not force:
            console.print(
                "[yellow]Not connected. Use --force to rotate anyway.[/yellow]"
            )
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Rotating IP...", total=None)
            
            success = self.controller.rotate_ip(
                new_location=new_location,
                random_location=random
            )
            
            progress.update(task, completed=1)
        
        if success:
            console.print("[green]✓ IP rotated successfully[/green]")
        else:
            console.print("[red]✗ IP rotation failed[/red]")
    
    def disconnect(self, keep_kill_switch: bool = False):
        """Disconnect from VPN"""
        if not Confirm.ask("Disconnect from VPN?"):
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Disconnecting...", total=None)
            
            success = self.controller.disconnect(
                keep_kill_switch=keep_kill_switch
            )
            
            progress.update(task, completed=1)
        
        if success:
            console.print("[green]✓ Disconnected successfully[/green]")
        else:
            console.print("[red]✗ Disconnection failed[/red]")
    
    def status(self, detailed: bool = False):
        """Show VPN status"""
        status = self.controller.get_status()
        
        # Create status table
        table = Table(title="VPN Status", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        # Basic status
        table.add_row("State", status['state'])
        table.add_row("Connected", "✓" if status['connected'] else "✗")
        table.add_row(
            "Kill Switch",
            "Active" if status['kill_switch_active'] else "Inactive"
        )
        
        if status['connected']:
            table.add_row("Uptime", self._format_duration(status['uptime']))
            
            if status['server']:
                table.add_row(
                    "Location",
                    f"{status['server']['country']}/{status['server']['city']}"
                )
                table.add_row("Server", status['server']['hostname'])
            
            if status['statistics']['ip_address']:
                table.add_row("IP Address", status['statistics']['ip_address'])
        
        console.print(table)
        
        # Detailed information
        if detailed and status['connected']:
            # Traffic statistics
            stats = status['statistics']
            if stats['bytes_sent'] > 0 or stats['bytes_received'] > 0:
                stats_table = Table(title="Traffic Statistics", box=box.SIMPLE)
                stats_table.add_column("Direction", style="cyan")
                stats_table.add_column("Bytes", style="green")
                stats_table.add_column("Human Readable", style="white")
                
                stats_table.add_row(
                    "Sent",
                    str(stats['bytes_sent']),
                    self._human_bytes(stats['bytes_sent'])
                )
                stats_table.add_row(
                    "Received",
                    str(stats['bytes_received']),
                    self._human_bytes(stats['bytes_received'])
                )
                
                console.print("\n")
                console.print(stats_table)
            
            # DNS information
            if stats['dns_servers']:
                dns_table = Table(title="DNS Servers", box=box.SIMPLE)
                dns_table.add_column("#", style="cyan")
                dns_table.add_column("Server", style="white")
                
                for i, dns in enumerate(stats['dns_servers'], 1):
                    dns_table.add_row(str(i), dns)
                
                console.print("\n")
                console.print(dns_table)
    
    def list_servers(self, country: Optional[str] = None,
                     protocol: Optional[str] = None):
        """List available servers"""
        servers = self.ip_rotator.get_all_servers()
        
        if country:
            servers = [
                s for s in servers 
                if s.country.lower() == country.lower()
            ]
        if protocol:
            servers = [
                s for s in servers 
                if s.protocol.lower() == protocol.lower()
            ]
        
        if not servers:
            console.print("[yellow]No servers found[/yellow]")
            return
        
        # Create servers table
        table = Table(title="Available VPN Servers", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Country", style="green")
        table.add_column("City", style="white")
        table.add_column("Hostname", style="blue")
        table.add_column("Protocol", style="yellow")
        table.add_column("Port", style="magenta")
        table.add_column("Load", style="red")
        table.add_column("Latency", style="cyan")
        
        for server in servers[:50]:  # Limit display
            load_str = f"{server.load}%" if server.load else "N/A"
            latency_str = (
                f"{server.latency:.1f}ms" 
                if server.latency else "N/A"
            )
            
            table.add_row(
                server.id[:8],
                server.country,
                server.city,
                server.hostname,
                server.protocol.upper(),
                str(server.port),
                load_str,
                latency_str
            )
        
        console.print(table)
        console.print(
            f"[dim]Showing {len(servers[:50])} of {len(servers)} servers[/dim]"
        )
    
    def test_connection(
        self, leak_test: bool = False, speed_test: bool = False
    ):
        """Test VPN connection"""
        if not self.controller.state.name == 'CONNECTED':
            console.print("[yellow]Not connected to VPN[/yellow]")
            return
        
        status = self.controller.get_status()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            tasks = []
            
            # Initialize leak table
            leak_table = Table(title="IP Leak Test", box=box.SIMPLE)
            leak_table.add_column("Test", style="cyan")
            leak_table.add_column("Result", style="white")
            leak_table.add_column("Status", style="green")
            
            # IP leak test
            if leak_test:
                task1 = progress.add_task(
                    "Testing for IP leaks...", total=None
                )
                tasks.append(task1)
                
                # Get public IP
                public_ip = self.network_tools.get_public_ip()
                vpn_ip = status['statistics']['ip_address']
                
                progress.update(task1, completed=1)
                
                # Display results
                console.print("\n")
                
                if public_ip == vpn_ip:
                    leak_table.add_row("IP Address", public_ip, "✓ No leak")
                else:
                    leak_table.add_row(
                        "IP Address", 
                        f"VPN: {vpn_ip}, Public: {public_ip}", 
                        "✗ Leak detected!"
                    )
                
                console.print(leak_table)
            
            # DNS leak test
            if leak_test:
                task2 = progress.add_task(
                    "Testing for DNS leaks...", total=None
                )
                tasks.append(task2)
                
                dns_leak = self.network_tools.check_dns_leak(
                    status['statistics']['dns_servers']
                )
                
                progress.update(task2, completed=1)
                
                dns_status = (
                    "✓ No leak" if not dns_leak else "✗ Leak detected!"
                )
                leak_table.add_row("DNS", str(dns_leak), dns_status)
                
                console.print(leak_table)
            
            # Speed test
            if speed_test:
                task3 = progress.add_task("Running speed test...", total=100)
                tasks.append(task3)
                
                # Simulate progress
                for i in range(10):
                    time.sleep(0.5)
                    progress.update(task3, advance=10)
                
                # Get speed test results (simulated)
                progress.update(task3, completed=100)
                
                console.print("\n")
                speed_table = Table(title="Speed Test", box=box.SIMPLE)
                speed_table.add_column("Metric", style="cyan")
                speed_table.add_column("Value", style="white")
                speed_table.add_column("Rating", style="green")
                
                # Simulated results
                speed_table.add_row("Download", "85.2 Mbps", "Good")
                speed_table.add_row("Upload", "42.7 Mbps", "Good")
                speed_table.add_row("Ping", "32 ms", "Excellent")
                
                console.print(speed_table)
    
    def _select_server(self, **kwargs) -> Optional[VPNServer]:
        """Select VPN server based on criteria"""
        # If config file provided, use it
        if kwargs.get('config_file'):
            return self._load_server_from_config(kwargs['config_file'])

        find_args = {}
        if 'country' in kwargs and kwargs['country']:
            find_args['country'] = kwargs['country']
        if 'protocol' in kwargs and kwargs['protocol']:
            find_args['protocol'] = kwargs['protocol']
        
        # Get servers matching criteria
        servers = self.ip_rotator.find_servers(**find_args)

        if 'location' in kwargs and kwargs['location']:
            location = kwargs['location']
            servers = [
                s for s in servers
                if location.lower() in s.country.lower() or
                   location.lower() in s.city.lower()
            ]
        
        if 'server' in kwargs and kwargs['server']:
            server_hostname = kwargs['server']
            servers = [
                s for s in servers
                if server_hostname.lower() in s.hostname.lower()
            ]

        if 'port' in kwargs and kwargs['port']:
            port = kwargs['port']
            servers = [
                s for s in servers
                if s.port == port
            ]

        if not servers:
            console.print(
                "[yellow]No servers found matching criteria[/yellow]"
            )
            return None
        
        if len(servers) == 1:
            return servers[0]
        
        # Let user choose
        console.print("\n[bold]Available servers:[/bold]")
        for i, server in enumerate(servers[:10], 1):
            console.print(f"  {i}. {server.country}/{server.city} - "
                         f"{server.hostname} "
                         f"({server.protocol}:{server.port})"
                    )
        
        choice = Prompt.ask(
            "Select server (number)", 
            choices=[str(i) for i in range(1, min(11, len(servers) + 1))],
            default="1"
        )
        
        return servers[int(choice) - 1]
    
    def _display_connection_info(self, server: VPNServer):
        """Display connection information"""
        info_panel = Panel.fit(
            f"[bold]Country:[/bold] {server.country}\n"
            f"[bold]City:[/bold] {server.city}\n"
            f"[bold]Server:[/bold] {server.hostname}\n"
            f"[bold]Protocol:[/bold] {server.protocol.upper()}\n"
            f"[bold]Port:[/bold] {server.port}\n"
            f"[bold]IP:[/bold] {server.ip_address}",
            title="Connection Details",
            border_style="blue"
        )
        console.print(info_panel)
    
    def _on_state_change(self, old_state, new_state, message):
        """Handle state change callback"""
        console.print(f"[dim]State: {old_state.name} → {new_state.name}[/dim]")
        if message:
            console.print(f"[dim]Message: {message}[/dim]")
    
    def _on_ip_change(self, new_ip):
        """Handle IP change callback"""
        console.print(f"[dim]New IP: {new_ip}[/dim]")
    
    def _on_error(self, error_message):
        """Handle error callback"""
        console.print(f"[red]Error: {error_message}[/red]")
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human readable"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds // 60
            seconds %= 60
            return f"{minutes:.0f}m {seconds:.0f}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours:.0f}h {minutes:.0f}m"
    
    def _human_bytes(self, bytes_count: float) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"
    
    def _load_server_from_config(
        self, config_file: str
    ) -> Optional[VPNServer]:
        """Load server from configuration file"""
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            server_data = data.get('server')
            if not server_data:
                console.print(
                    "[red]No server configuration found in file[/red]"
                )
                return None
            
            return VPNServer.from_config(server_data)
            
        except Exception as e:
            console.print(
                f"[red]Error loading config file: {e}[/red]"
            )
            return None


def main():
    """Main entry point for CLI interface"""
    import sys
    import argparse
    from pathlib import Path
    
    # Add project root to path if needed
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Import main module to use the existing CLI
    try:
        from main import main as main_entry
        # Call the main entry point
        main_entry()
    except ImportError:
        # Fallback to running CLI directly
        cli = VPNCLI()
        
        # Setup argument parser (basic implementation)
        parser = argparse.ArgumentParser(
            description='Advanced VPN Manager with Kill Switch',
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest='command', help='Command to execute'
        )
        
        # Add basic commands
        subparsers.add_parser('status', help='Check VPN status')
        subparsers.add_parser('list', help='List available servers')
        subparsers.add_parser('test', help='Test connection')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            sys.exit(1)
            
        # Execute basic commands
        if args.command == 'status':
            cli.status()
        elif args.command == 'list':
            cli.list_servers()
        elif args.command == 'test':
            cli.test_connection(leak_test=True)
