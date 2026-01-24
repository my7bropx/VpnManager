#!/usr/bin/env python3
"""
VPN Manager - Robust OpenVPN client with kill switch and IP rotation
"""

import sys
import signal
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from vpn_manager.utils.logging_setup import setup_file_logging, set_logging_level

def signal_handler(signum, frame):
    """Handle termination signals gracefully"""
    print(f"\nReceived signal {signum}, shutting down...")
    from vpn_manager.core.vpn_controller import VPNController
    if VPNController._instance:
        VPNController._instance.emergency_disconnect()
    sys.exit(0)

def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description='Advanced VPN Manager with Kill Switch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s connect --location "Netherlands" --protocol udp
  %(prog)s rotate --random
  %(prog)s status --detailed
  %(prog)s disconnect --kill-switch
  %(prog)s tui
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(
        dest='command', 
        help='Command to execute'
    )
    
    # Connect command
    connect_parser = subparsers.add_parser('connect', help='Connect to VPN')
    connect_parser.add_argument('--location', help='VPN server location')
    connect_parser.add_argument(
        '--country', 
        help='Country code (e.g., US, NL)'
    )
    connect_parser.add_argument('--server', help='Specific server address')
    connect_parser.add_argument(
        '--protocol',
        help='VPN protocol',
        choices=['tcp', 'udp'],
        default='udp'
    )
    connect_parser.add_argument('--port', type=int, help='Port number')
    connect_parser.add_argument('--config', help='Path to .ovpn config file')
    connect_parser.add_argument('--no-kill-switch', action='store_true', 
                               help='Disable kill switch')
    connect_parser.add_argument('--dns', nargs='+', default=['1.1.1.1', '8.8.8.8'],
                               help='DNS servers to use')
    
    # Rotate command
    rotate_parser = subparsers.add_parser('rotate', help='Rotate IP address')
    rotate_parser.add_argument('--location', help='New location')
    rotate_parser.add_argument(
        '--random', 
        action='store_true',
        help='Random location'
    )
    rotate_parser.add_argument(
        '--force', 
        action='store_true',
        help='Force rotation even if connected'
    )
    
    # Disconnect command
    disconnect_parser = subparsers.add_parser(
        'disconnect', 
        help='Disconnect VPN'
    )
    disconnect_parser.add_argument(
        '--kill-switch', 
        action='store_true',
        help='Keep kill switch active'
    )
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check VPN status')
    status_parser.add_argument('--detailed', action='store_true',
                              help='Detailed status information')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available servers')
    list_parser.add_argument('--country', help='Filter by country')
    list_parser.add_argument('--protocol', help='Filter by protocol')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test connection')
    test_parser.add_argument('--leak-test', action='store_true',
                            help='Test for DNS/IP leaks')
    test_parser.add_argument('--speed-test', action='store_true',
                            help='Run speed test')

    # TUI command
    tui_parser = subparsers.add_parser('tui', help='Launch Terminal User Interface')
    tui_parser.add_argument(
        '--log-file',
        type=Path,
        default=Path('/home/my7bropxki/.gemini/tmp/4ef9b0c6423a16f315f0c1798e874a55791df4486bada1081da9f7422d2a5776/vpn-manager.log'),
        help='Path to log file'
    )
    tui_parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set logging level'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_file_logging(__name__, args.log_file, args.log_level)
    set_logging_level(args.log_level)
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        from vpn_manager.cli.interface import VPNCLI
        from vpn_manager.ui.app import main as tui_main
        # Initialize CLI
        cli = VPNCLI()
        
        # Execute command
        if args.command == 'connect':
            cli.connect(
                location=args.location,
                country=args.country,
                server=args.server,
                protocol=args.protocol,
                port=args.port,
                config_file=args.config,
                enable_kill_switch=not args.no_kill_switch,
                dns_servers=args.dns
            )
        elif args.command == 'rotate':
            cli.rotate_ip(
                new_location=args.location,
                random=args.random,
                force=args.force
            )
        elif args.command == 'disconnect':
            cli.disconnect(keep_kill_switch=args.kill_switch)
        elif args.command == 'status':
            cli.status(detailed=args.detailed)
        elif args.command == 'list':
            cli.list_servers(country=args.country, protocol=args.protocol)
        elif args.command == 'test':
            cli.test_connection(
                leak_test=args.leak_test,
                speed_test=args.speed_test
            )
        elif args.command == 'tui':
            try:
                tui_main()
            except Exception as e:
                logger.error(f"TUI error: {e}", exc_info=True)
                sys.exit(1)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()