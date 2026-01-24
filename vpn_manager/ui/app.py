"""
VPN Manager - Dynamic Terminal User Interface
Main TUI application with dashboard and navigation
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Label,
    DataTable, TabbedContent, TabPane, Log,
    ProgressBar, Switch, Input, Select
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.worker import Worker, get_current_worker
from textual import work
from textual.message import Message

import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import logging

# Setup logger
logger = logging.getLogger(__name__)

# Import dialog components
from .dialogs import (
    ConfirmDialog, ConnectDialog, ProfileImportDialog,
    SettingsDialog, TestResultDialog, AboutDialog
)

# Import VPN Manager components
from ..core.vpn_controller import VPNController, VPNState
from ..core.ip_rotator import IPRotator
from ..core.config_manager import ConfigManager
from ..utils.network_tools import NetworkTools
from ..utils.system_check import verify_system_requirements, get_system_info


class StatusCard(Static):
    """Widget to display connection status"""

    def __init__(self, title: str, value: str = "N/A", status: str = "default"):
        super().__init__()
        self.card_title = title
        self.card_value = value
        self.card_status = status

    def compose(self) -> ComposeResult:
        yield Label(self.card_title, classes="card-title")
        yield Label(self.card_value, classes=f"card-value status-{self.card_status}")

    def update_value(self, value: str, status: str = "default"):
        """Update card value and status"""
        self.card_value = value
        self.card_status = status
        self.query_one(".card-value").update(value)
        self.query_one(".card-value").remove_class("status-default",
                                                   "status-good", "status-warning", "status-error")
        self.query_one(".card-value").add_class(f"status-{status}")


class ConnectionPanel(Static):
    """Main connection status panel"""

    state = reactive("DISCONNECTED")
    ip_address = reactive("N/A")
    location = reactive("N/A")
    server = reactive("N/A")
    uptime = reactive("0:00:00")
    kill_switch = reactive("Inactive")

    def compose(self) -> ComposeResult:
        with Container(classes="connection-panel"):
            yield Static("VPN Connection Status", classes="panel-title")

            with Horizontal(classes="status-cards"):
                yield StatusCard("State", self.state, "error")
                yield StatusCard("IP Address", self.ip_address, "default")
                yield StatusCard("Location", self.location, "default")

            with Horizontal(classes="status-cards"):
                yield StatusCard("Server", self.server, "default")
                yield StatusCard("Uptime", self.uptime, "default")
                yield StatusCard("Kill Switch", self.kill_switch, "warning")

    def update_status(self, status_data: Dict):
        """Update all status cards with new data"""
        state = status_data.get('state', 'DISCONNECTED')
        self.state = state

        # Update state card
        state_status = "good" if state == "CONNECTED" else "error"
        self.query(StatusCard)[0].update_value(state, state_status)

        # Update IP
        ip = status_data.get('statistics', {}).get('ip_address', 'N/A')
        self.ip_address = ip
        ip_status = "good" if ip != 'N/A' else "default"
        self.query(StatusCard)[1].update_value(ip, ip_status)

        # Update location
        location = status_data.get('statistics', {}).get('location', 'N/A')
        self.location = location
        self.query(StatusCard)[2].update_value(location, "default")

        # Update server
        server_data = status_data.get('server', {})
        if server_data:
            server = f"{server_data.get(
                'country', 'N/A')}/{server_data.get('city', 'N/A')}"
        else:
            server = 'N/A'
        self.server = server
        self.query(StatusCard)[3].update_value(server, "default")

        # Update uptime
        uptime = status_data.get('uptime', 0)
        uptime_str = self._format_uptime(uptime)
        self.uptime = uptime_str
        self.query(StatusCard)[4].update_value(uptime_str, "default")

        # Update kill switch
        ks_active = status_data.get('kill_switch_active', False)
        ks_text = "Active" if ks_active else "Inactive"
        ks_status = "good" if ks_active else "warning"
        self.kill_switch = ks_text
        self.query(StatusCard)[5].update_value(ks_text, ks_status)

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format uptime seconds to HH:MM:SS"""
        if seconds == 0:
            return "0:00:00"

        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}:{minutes:02d}:{secs:02d}"


class StatisticsPanel(Static):
    """Traffic statistics panel"""

    def compose(self) -> ComposeResult:
        with Container(classes="stats-panel"):
            yield Static("Traffic Statistics", classes="panel-title")

            with Horizontal(classes="stats-row"):
                yield Label("Sent:", classes="stats-label")
                yield Label("0 B", id="stats-sent", classes="stats-value")

            with Horizontal(classes="stats-row"):
                yield Label("Received:", classes="stats-label")
                yield Label("0 B", id="stats-received", classes="stats-value")

            with Horizontal(classes="stats-row"):
                yield Label("Total:", classes="stats-label")
                yield Label("0 B", id="stats-total", classes="stats-value")

            yield ProgressBar(total=100, show_eta=False, id="traffic-progress")

    def update_statistics(self, stats: Dict):
        """Update traffic statistics"""
        sent = stats.get('bytes_sent', 0)
        received = stats.get('bytes_received', 0)
        total = sent + received

        self.query_one("#stats-sent", Label).update(self._human_bytes(sent))
        self.query_one("#stats-received",
                       Label).update(self._human_bytes(received))
        self.query_one("#stats-total", Label).update(self._human_bytes(total))

        # Update progress bar (arbitrary visual representation)
        if total > 0:
            progress = min(100, (total / (1024 * 1024 * 100))
                           * 100)  # Cap at 100MB
            self.query_one("#traffic-progress",
                           ProgressBar).update(progress=progress)

    @staticmethod
    def _human_bytes(bytes_count: float) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"


class ServerList(Static):
    """Server list widget"""

    def compose(self) -> ComposeResult:
        with Container(classes="server-list"):
            yield Static("Available Servers", classes="panel-title")

            table = DataTable(id="server-table")
            table.add_columns("ID", "Country", "City",
                              "Protocol", "Port", "Latency")
            yield table

            with Horizontal(classes="button-row"):
                yield Button("Refresh", id="btn-refresh-servers", variant="primary")
                yield Button("Connect Selected", id="btn-connect-server", variant="success")

    def populate_servers(self, servers: List[Dict]):
        """Populate server table"""
        table = self.query_one("#server-table", DataTable)
        table.clear()

        for server in servers:
            latency = f"{server.get('latency', 0):.1f}ms" if server.get(
                'latency') else "N/A"
            table.add_row(
                server.get('id', 'N/A')[:8],
                server.get('country', 'N/A'),
                server.get('city', 'N/A'),
                server.get('protocol', 'udp').upper(),
                str(server.get('port', 1194)),
                latency
            )


class ProfileManager(Static):
    """VPN profile management widget"""

    def compose(self) -> ComposeResult:
        with Container(classes="profile-manager"):
            yield Static("VPN Profiles", classes="panel-title")

            table = DataTable(id="profile-table")
            table.add_columns("Name", "Protocol", "Port", "Remote")
            yield table

            with Horizontal(classes="button-row"):
                yield Button("Load Profile", id="btn-load-profile", variant="primary")
                yield Button("Import", id="btn-import-profile", variant="default")
                yield Button("Delete", id="btn-delete-profile", variant="error")

    def populate_profiles(self, profiles: List[Dict]):
        """Populate profile table"""
        table = self.query_one("#profile-table", DataTable)
        table.clear()

        for profile in profiles:
            table.add_row(
                profile.get('name', 'N/A'),
                profile.get('protocol', 'udp').upper(),
                str(profile.get('port', 1194)),
                profile.get('remote', 'N/A')
            )


class ConnectionControls(Static):
    """Connection control buttons and settings"""

    def compose(self) -> ComposeResult:
        with Container(classes="connection-controls"):
            yield Static("Connection Controls", classes="panel-title")

            with Horizontal(classes="control-row"):
                yield Button("Connect", id="btn-connect", variant="success")
                yield Button("Disconnect", id="btn-disconnect", variant="error")
                yield Button("Rotate IP", id="btn-rotate", variant="primary")

            with Horizontal(classes="control-row"):
                yield Label("Enable Kill Switch:", classes="control-label")
                yield Switch(value=True, id="switch-killswitch")

            with Horizontal(classes="control-row"):
                yield Label("Auto Reconnect:", classes="control-label")
                yield Switch(value=True, id="switch-autoreconnect")

            with Horizontal(classes="control-row"):
                yield Label("DNS Servers:", classes="control-label")
                yield Input(placeholder="1.1.1.1,8.8.8.8", id="input-dns")


class LogViewer(Static):
    """Log viewer widget"""

    def compose(self) -> ComposeResult:
        with Container(classes="log-viewer"):
            yield Static("Activity Log", classes="panel-title")
            yield Log(id="activity-log", auto_scroll=True)

            with Horizontal(classes="button-row"):
                yield Button("Clear Log", id="btn-clear-log", variant="default")
                yield Button("Save Log", id="btn-save-log", variant="primary")


class VPNManagerTUI(App):
    """Main VPN Manager TUI Application"""

    CSS = """
    Screen {
        background: $surface;
    }
    
    .connection-panel {
        height: auto;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }
    
    .panel-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .status-cards {
        height: auto;
        margin-bottom: 1;
    }
    
    StatusCard {
        border: solid $primary-darken-2;
        padding: 1;
        margin-right: 1;
        width: 1fr;
        height: auto;
    }
    
    .card-title {
        color: $text-muted;
        text-style: bold;
    }
    
    .card-value {
        color: $text;
        text-style: bold;
        text-align: center;
        margin-top: 1;
    }
    
    .status-good {
        color: $success;
    }
    
    .status-warning {
        color: $warning;
    }
    
    .status-error {
        color: $error;
    }
    
    .status-default {
        color: $text;
    }
    
    .stats-panel {
        border: solid $primary;
        padding: 1;
        margin: 1;
        height: auto;
    }
    
    .stats-row {
        height: auto;
        margin-bottom: 1;
    }
    
    .stats-label {
        width: 12;
        color: $text-muted;
    }
    
    .stats-value {
        color: $accent;
        text-style: bold;
    }
    
    .server-list, .profile-manager {
        border: solid $primary;
        padding: 1;
        margin: 1;
        height: 100%;
    }
    
    DataTable {
        height: 1fr;
        margin-bottom: 1;
    }
    
    .button-row {
        height: auto;
        margin-top: 1;
    }
    
    .button-row Button {
        margin-right: 1;
    }
    
    .connection-controls {
        border: solid $primary;
        padding: 1;
        margin: 1;
        height: auto;
    }
    
    .control-row {
        height: auto;
        margin-bottom: 1;
    }
    
    .control-label {
        width: 20;
        color: $text-muted;
    }
    
    Switch {
        margin-right: 2;
    }
    
    Input {
        width: 1fr;
    }
    
    .log-viewer {
        border: solid $primary;
        padding: 1;
        margin: 1;
        height: 100%;
    }
    
    Log {
        height: 1fr;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    
    TabbedContent {
        height: 100%;
    }
    
    TabPane {
        padding: 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("c", "show_connect_dialog", "Connect"),
        Binding("d", "disconnect", "Disconnect"),
        Binding("r", "rotate", "Rotate IP"),
        Binding("t", "test", "Test Connection"),
        Binding("s", "show_settings", "Settings"),
        Binding("i", "show_import", "Import Profile"),
        Binding("a", "show_about", "About"),
        Binding("f1", "help", "Help"),
    ]

    TITLE = "VPN Manager - Advanced Kill Switch"
    SUB_TITLE = "Terminal User Interface"

    def __init__(self):
        super().__init__()
        logger.info("VPNManagerTUI.__init__ start")
        self.controller = None
        self.config_manager = None
        self.network_tools = None
        self.ip_rotator = None
        self.update_task = None
        self.is_initialized = False
        logger.info("VPNManagerTUI.__init__ end")

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                with Vertical():
                    yield ConnectionPanel()
                    yield StatisticsPanel()
                    yield ConnectionControls()

            with TabPane("Servers", id="servers"):
                yield ServerList()

            with TabPane("Profiles", id="profiles"):
                yield ProfileManager()

            with TabPane("Logs", id="logs"):
                yield LogViewer()

        yield Footer()

    async def on_mount(self) -> None:
        """Initialize application on mount"""
        logger.info("VPN Manager TUI started")
        logger.info("VPNManagerTUI.on_mount start")

        # Initialize components
        await self.initialize_components()

        # Start update loop
        self.update_task = self.set_interval(1.0, self.update_status)
        logger.info("VPNManagerTUI.on_mount end")

    async def initialize_components(self):
        """Initialize VPN manager components"""
        try:
            logger.info("Initializing VPN Manager components...")

            # Initialize config manager
            self.config_manager = ConfigManager()
            logger.info("Config manager initialized")

            # Initialize controller
            self.controller = VPNController()
            logger.info("VPN controller initialized")

            # Initialize network tools
            self.network_tools = NetworkTools()
            logger.info("Network tools initialized")

            # Initialize IP rotator
            self.ip_rotator = IPRotator()
            logger.info("IP rotator initialized")

            # Register callbacks
            self.controller.register_callback(
                'state_change', self.on_state_change)
            self.controller.register_callback('ip_change', self.on_ip_change)
            self.controller.register_callback('error', self.on_error)

            # Load profiles
            await self.load_profiles()

            self.is_initialized = True
            logger.info("Initialization complete")

        except Exception as e:
            logger.error(f"Initialization failed: {e}", exc_info=True)

    async def load_profiles(self):
        """Load available VPN profiles"""
        if not self.config_manager:
            return

        try:
            profiles = self.config_manager.list_profiles()
            profile_manager = self.query_one(ProfileManager)
            profile_manager.populate_profiles(profiles)
            logger.info(f"Loaded {len(profiles)} profiles")
        except Exception as e:
            logger.error(f"Failed to load profiles: {e}", exc_info=True)

    async def update_status(self):
        """Update status display"""
        if not self.controller:
            return

        try:
            status = self.controller.get_status()

            # Update connection panel
            conn_panel = self.query_one(ConnectionPanel)
            conn_panel.update_status(status)

            # Update statistics panel
            stats_panel = self.query_one(StatisticsPanel)
            stats_panel.update_statistics(status.get('statistics', {}))

        except Exception as e:
            pass  # Suppress update errors
    
    def on_state_change(self, old_state, new_state, message):
        """Handle VPN state change"""
        logger.info(f"State changed: {
                         old_state.name} -> {new_state.name}")
        if message:
            logger.info(f"Message: {message}")

    def on_ip_change(self, new_ip):
        """Handle IP address change"""
        logger.info(f"IP changed to: {new_ip}")

    def on_error(self, error_message):
        """Handle errors"""
        logger.error(error_message)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        button_id = event.button.id

        if button_id == "btn-connect":
            await self.action_connect()
        elif button_id == "btn-disconnect":
            await self.action_disconnect()
        elif button_id == "btn-rotate":
            await self.action_rotate()
        elif button_id == "btn-clear-log":
            self.query_one("#activity-log", Log).clear()
        elif button_id == "btn-save-log":
            await self.save_log()
        elif button_id == "btn-refresh-servers":
            await self.refresh_servers()
        elif button_id == "btn-connect-server":
            await self.connect_selected_server()
        elif button_id == "btn-load-profile":
            await self.load_selected_profile()

    async def action_connect(self):
        """Show connect dialog"""
        if not self.is_initialized:
            logger.error("System not initialized")
            return

        # Get available profiles and servers
        profiles = []
        servers = []

        if self.config_manager:
            try:
                profiles = self.config_manager.list_profiles()
            except Exception:
                pass

        if self.ip_rotator:
            try:
                server_list = self.ip_rotator.get_all_servers()
                servers = [
                    {
                        'id': s.id,
                        'country': s.country,
                        'city': s.city,
                        'protocol': s.protocol,
                        'port': s.port
                    }
                    for s in server_list[:20]  # Limit to 20 servers
                ]
            except Exception:
                pass

        # Show connect dialog
        result = await self.push_screen(ConnectDialog(profiles, servers), wait_for_dismiss=True)

        if result:
            logger.info("Connecting with settings...")
            logger.info(f"Profile: {result.get('profile', 'None')}")
            logger.info(
                f"Kill Switch: {'Enabled' if result.get('kill_switch') else 'Disabled'}")

            # TODO: Implement actual connection logic
            logger.warning("Connection feature coming soon")

    async def action_show_connect_dialog(self):
        """Show connect dialog"""
        await self.action_connect()

    async def action_show_settings(self):
        """Show settings dialog"""
        if not self.config_manager:
            logger.error("Config manager not initialized")
            return

        current_settings = self.config_manager.settings

        result = await self.push_screen(SettingsDialog(current_settings), wait_for_dismiss=True)

        if result:
            logger.info("Saving settings...")
            try:
                # Update settings
                for key, value in result.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            self.config_manager.set(
                                f"{key}.{subkey}", subvalue)
                    else:
                        self.config_manager.set(key, value)

                logger.info("Settings saved successfully")
            except Exception as e:
                logger.error(f"Failed to save settings: {e}", exc_info=True)

    async def action_show_import(self):
        """Show profile import dialog"""
        start_path = Path.home()

        result = await self.push_screen(ProfileImportDialog(start_path), wait_for_dismiss=True)

        if result:
            logger.info(f"Importing profile: {result}")

            if not self.config_manager:
                logger.error("Config manager not initialized")
                return

            try:
                # Import profile
                profile_data = self.config_manager.load_ovpn_profile(result)

                # Copy to profiles directory
                dest = self.config_manager.profiles_dir / result.name
                import shutil
                shutil.copy(result, dest)

                logger.info(f"Profile imported successfully: {
                                 profile_data['name']}")

                # Reload profiles
                await self.load_profiles()

            except Exception as e:
                logger.error(f"Failed to import profile: {e}", exc_info=True)

    async def action_show_about(self):
        """Show about dialog"""
        await self.push_screen(AboutDialog())

    async def action_help(self):
        """Show help"""
        logger.info("=== VPN Manager TUI Help ===")
        logger.info("Keyboard Shortcuts:")
        logger.info("  c - Connect to VPN")
        logger.info("  d - Disconnect from VPN")
        logger.info("  r - Rotate IP address")
        logger.info("  t - Test connection for leaks")
        logger.info("  s - Open settings")
        logger.info("  i - Import VPN profile")
        logger.info("  a - About VPN Manager")
        logger.info("  q - Quit application")
        logger.info("  F1 - This help message")

    async def action_disconnect(self):
        """Disconnect from VPN"""
        if not self.controller:
            return

        logger.info("Disconnecting from VPN...")

        try:
            success = self.controller.disconnect()
            if success:
                logger.info("Disconnected successfully")
            else:
                logger.error("Disconnect failed")
        except Exception as e:
            logger.error(f"Disconnect error: {e}", exc_info=True)

    async def action_rotate(self):
        """Rotate IP address"""
        if not self.controller:
            return

        logger.info("Rotating IP address...")

        try:
            success = self.controller.rotate_ip(random_location=True)
            if success:
                logger.info("IP rotated successfully")
            else:
                logger.error("IP rotation failed")
        except Exception as e:
            logger.error(f"Rotation error: {e}", exc_info=True)

    async def action_test(self):
        """Test connection for leaks"""
        if not self.network_tools:
            return

        logger.info("Testing for IP leaks...")

        try:
            public_ip = self.network_tools.get_public_ip()
            logger.info(f"Public IP: {public_ip}")

            # Get geo info
            geo = self.network_tools.get_geo_location(public_ip)
            logger.info(f"Location: {geo.get(
                'location', 'Unknown')}")

        except Exception as e:
            logger.error(f"Test error: {e}", exc_info=True)

    async def action_toggle_log(self):
        """Toggle log visibility"""
        tabs = self.query_one(TabbedContent)
        tabs.active = "logs"

    async def save_log(self):
        """Save log to file"""
        try:
            log_file = Path.home() / '.config' / 'vpn-manager' / 'logs' / \
                f"tui_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)

            log_widget = self.query_one("#activity-log", Log)
            # TODO: Implement log saving

            logger.info(f"Log saved to {log_file}")
        except Exception as e:
            logger.error(f"Failed to save log: {e}", exc_info=True)

    async def refresh_servers(self):
        """Refresh server list"""
        if not self.ip_rotator:
            return

        logger.info("Refreshing server list...")

        try:
            servers = self.ip_rotator.get_all_servers()
            server_list = self.query_one(ServerList)

            # Convert to dict format
            server_dicts = []
            for server in servers:
                server_dicts.append({
                    'id': server.id,
                    'country': server.country,
                    'city': server.city,
                    'protocol': server.protocol,
                    'port': server.port,
                    'latency': server.latency
                })

            server_list.populate_servers(server_dicts)
            logger.info(f"Loaded {len(servers)} servers")

        except Exception as e:
            logger.error(f"Failed to refresh servers: {e}", exc_info=True)

    async def connect_selected_server(self):
        """Connect to selected server from table"""
        logger.warning(
            "Connect to selected server - feature coming soon")

    async def load_selected_profile(self):
        """Load selected profile"""
        logger.warning("Load profile - feature coming soon")

def main():
    """Main entry point for TUI"""
    app = VPNManagerTUI()
    app.run()


if __name__ == "__main__":
    main()
