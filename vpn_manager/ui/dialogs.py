"""
VPN Manager TUI - Dialog Components
Modal dialogs for user interaction
"""

from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal, Grid
from textual.widgets import Button, Static, Label, Input, Select, Switch, DirectoryTree
from textual.screen import ModalScreen
from typing import Optional, Callable, List, Dict
from pathlib import Path


class ConfirmDialog(ModalScreen):
    """Confirmation dialog"""
    
    def __init__(
        self,
        title: str,
        message: str,
        on_confirm: Optional[Callable] = None,
        on_cancel: Optional[Callable] = None
    ):
        super().__init__()
        self.dialog_title = title
        self.dialog_message = message
        self.on_confirm_callback = on_confirm
        self.on_cancel_callback = on_cancel
    
    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Static(self.dialog_title, id="dialog-title")
            yield Static(self.dialog_message, id="dialog-message")
            with Horizontal(id="dialog-buttons"):
                yield Button("Confirm", variant="success", id="confirm")
                yield Button("Cancel", variant="default", id="cancel")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            if self.on_confirm_callback:
                self.on_confirm_callback()
            self.dismiss(True)
        else:
            if self.on_cancel_callback:
                self.on_cancel_callback()
            self.dismiss(False)


class ConnectDialog(ModalScreen):
    """Connection dialog with options"""
    
    CSS = """
    #connect-dialog {
        align: center middle;
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    
    #connect-title {
        width: 100%;
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .connect-row {
        height: auto;
        margin-bottom: 1;
    }
    
    .connect-label {
        width: 20;
        color: $text-muted;
    }
    
    .connect-buttons {
        margin-top: 1;
        height: auto;
    }
    
    .connect-buttons Button {
        margin-right: 1;
    }
    """
    
    def __init__(self, profiles: List[Dict], servers: List[Dict]):
        super().__init__()
        self.profiles = profiles
        self.servers = servers
        self.selected_profile = None
        self.selected_server = None
    
    def compose(self) -> ComposeResult:
        with Container(id="connect-dialog"):
            yield Static("Connect to VPN", id="connect-title")
            
            # Profile selection
            with Horizontal(classes="connect-row"):
                yield Label("Profile:", classes="connect-label")
                profile_options = [(p['name'], p['name']) for p in self.profiles]
                if not profile_options:
                    profile_options = [("None", "none")]
                yield Select(profile_options, id="select-profile", allow_blank=True)
            
            # Server selection
            with Horizontal(classes="connect-row"):
                yield Label("Or Server:", classes="connect-label")
                server_options = [
                    (f"{s['country']} - {s['city']}", s['id']) 
                    for s in self.servers
                ]
                if not server_options:
                    server_options = [("None", "none")]
                yield Select(server_options, id="select-server", allow_blank=True)
            
            # Kill switch
            with Horizontal(classes="connect-row"):
                yield Label("Kill Switch:", classes="connect-label")
                yield Switch(value=True, id="switch-ks")
            
            # Auto-reconnect
            with Horizontal(classes="connect-row"):
                yield Label("Auto-Reconnect:", classes="connect-label")
                yield Switch(value=True, id="switch-autoreconnect")
            
            # DNS servers
            with Horizontal(classes="connect-row"):
                yield Label("DNS Servers:", classes="connect-label")
                yield Input(placeholder="1.1.1.1,8.8.8.8", id="input-dns-dialog")
            
            # Buttons
            with Horizontal(classes="connect-buttons"):
                yield Button("Connect", variant="success", id="btn-dialog-connect")
                yield Button("Cancel", variant="default", id="btn-dialog-cancel")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-dialog-connect":
            # Gather settings
            settings = {
                'profile': self.query_one("#select-profile", Select).value,
                'server': self.query_one("#select-server", Select).value,
                'kill_switch': self.query_one("#switch-ks", Switch).value,
                'auto_reconnect': self.query_one("#switch-autoreconnect", Switch).value,
                'dns': self.query_one("#input-dns-dialog", Input).value
            }
            self.dismiss(settings)
        else:
            self.dismiss(None)


class ProfileImportDialog(ModalScreen):
    """Dialog for importing VPN profiles"""
    
    CSS = """
    #import-dialog {
        align: center middle;
        width: 70;
        height: 30;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    
    #import-title {
        width: 100%;
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    DirectoryTree {
        height: 1fr;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }
    
    .import-buttons {
        height: auto;
    }
    
    .import-buttons Button {
        margin-right: 1;
    }
    """
    
    def __init__(self, start_path: Path):
        super().__init__()
        self.start_path = start_path
        self.selected_file = None
    
    def compose(self) -> ComposeResult:
        with Container(id="import-dialog"):
            yield Static("Select VPN Profile (.ovpn)", id="import-title")
            yield DirectoryTree(str(self.start_path), id="profile-tree")
            
            with Horizontal(classes="import-buttons"):
                yield Button("Import", variant="success", id="btn-import")
                yield Button("Cancel", variant="default", id="btn-cancel-import")
    
    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.selected_file = event.path
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-import":
            if self.selected_file and str(self.selected_file).endswith('.ovpn'):
                self.dismiss(self.selected_file)
            else:
                self.dismiss(None)
        else:
            self.dismiss(None)


class SettingsDialog(ModalScreen):
    """Settings dialog"""
    
    CSS = """
    #settings-dialog {
        align: center middle;
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    
    #settings-title {
        width: 100%;
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .settings-section {
        border: solid $primary-darken-2;
        padding: 1;
        margin-bottom: 1;
    }
    
    .settings-section-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .settings-row {
        height: auto;
        margin-bottom: 1;
    }
    
    .settings-label {
        width: 25;
        color: $text-muted;
    }
    
    .settings-buttons {
        margin-top: 1;
        height: auto;
    }
    
    .settings-buttons Button {
        margin-right: 1;
    }
    """
    
    def __init__(self, current_settings: Dict):
        super().__init__()
        self.current_settings = current_settings
    
    def compose(self) -> ComposeResult:
        with Container(id="settings-dialog"):
            yield Static("VPN Manager Settings", id="settings-title")
            
            # General settings
            with Container(classes="settings-section"):
                yield Static("General", classes="settings-section-title")
                
                with Horizontal(classes="settings-row"):
                    yield Label("Log Level:", classes="settings-label")
                    yield Select(
                        [("DEBUG", "DEBUG"), ("INFO", "INFO"), 
                         ("WARNING", "WARNING"), ("ERROR", "ERROR")],
                        value=self.current_settings.get('log_level', 'INFO'),
                        id="select-loglevel"
                    )
                
                with Horizontal(classes="settings-row"):
                    yield Label("Connection Timeout:", classes="settings-label")
                    yield Input(
                        value=str(self.current_settings.get('connection_timeout', 60)),
                        id="input-timeout"
                    )
            
            # Kill Switch settings
            with Container(classes="settings-section"):
                yield Static("Kill Switch", classes="settings-section-title")
                
                with Horizontal(classes="settings-row"):
                    yield Label("Enabled by Default:", classes="settings-label")
                    yield Switch(
                        value=self.current_settings.get('kill_switch', {}).get('enabled', True),
                        id="switch-ks-default"
                    )
                
                with Horizontal(classes="settings-row"):
                    yield Label("Strict Mode:", classes="settings-label")
                    yield Switch(
                        value=self.current_settings.get('kill_switch', {}).get('strict_mode', False),
                        id="switch-strict"
                    )
                
                with Horizontal(classes="settings-row"):
                    yield Label("Allow LAN:", classes="settings-label")
                    yield Switch(
                        value=self.current_settings.get('kill_switch', {}).get('allow_lan', True),
                        id="switch-allow-lan"
                    )
            
            # IP Rotation settings
            with Container(classes="settings-section"):
                yield Static("IP Rotation", classes="settings-section-title")
                
                with Horizontal(classes="settings-row"):
                    yield Label("Auto Rotation:", classes="settings-label")
                    yield Switch(
                        value=self.current_settings.get('ip_rotation', {}).get('enabled', False),
                        id="switch-rotation"
                    )
                
                with Horizontal(classes="settings-row"):
                    yield Label("Rotation Interval (sec):", classes="settings-label")
                    yield Input(
                        value=str(self.current_settings.get('ip_rotation', {}).get('interval', 3600)),
                        id="input-rotation-interval"
                    )
            
            # DNS settings
            with Container(classes="settings-section"):
                yield Static("DNS", classes="settings-section-title")
                
                with Horizontal(classes="settings-row"):
                    yield Label("Leak Protection:", classes="settings-label")
                    yield Switch(
                        value=self.current_settings.get('dns', {}).get('leak_protection', True),
                        id="switch-dns-protection"
                    )
                
                with Horizontal(classes="settings-row"):
                    yield Label("Custom Servers:", classes="settings-label")
                    dns_servers = self.current_settings.get('dns', {}).get('custom_servers', [])
                    dns_str = ','.join(dns_servers) if dns_servers else '1.1.1.1,8.8.8.8'
                    yield Input(
                        value=dns_str,
                        id="input-dns-servers"
                    )
            
            # Buttons
            with Horizontal(classes="settings-buttons"):
                yield Button("Save", variant="success", id="btn-save-settings")
                yield Button("Cancel", variant="default", id="btn-cancel-settings")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save-settings":
            # Gather all settings
            settings = {
                'log_level': self.query_one("#select-loglevel", Select).value,
                'connection_timeout': int(self.query_one("#input-timeout", Input).value or 60),
                'kill_switch': {
                    'enabled': self.query_one("#switch-ks-default", Switch).value,
                    'strict_mode': self.query_one("#switch-strict", Switch).value,
                    'allow_lan': self.query_one("#switch-allow-lan", Switch).value,
                },
                'ip_rotation': {
                    'enabled': self.query_one("#switch-rotation", Switch).value,
                    'interval': int(self.query_one("#input-rotation-interval", Input).value or 3600),
                },
                'dns': {
                    'leak_protection': self.query_one("#switch-dns-protection", Switch).value,
                    'custom_servers': [
                        s.strip() 
                        for s in self.query_one("#input-dns-servers", Input).value.split(',')
                    ]
                }
            }
            self.dismiss(settings)
        else:
            self.dismiss(None)


class TestResultDialog(ModalScreen):
    """Dialog to show connection test results"""
    
    CSS = """
    #test-dialog {
        align: center middle;
        width: 50;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    
    #test-title {
        width: 100%;
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .test-result-row {
        height: auto;
        margin-bottom: 1;
    }
    
    .test-result-label {
        width: 20;
        color: $text-muted;
    }
    
    .test-result-value {
        color: $text;
    }
    
    .test-result-pass {
        color: $success;
        text-style: bold;
    }
    
    .test-result-fail {
        color: $error;
        text-style: bold;
    }
    
    .test-buttons {
        margin-top: 1;
        height: auto;
    }
    """
    
    def __init__(self, results: Dict):
        super().__init__()
        self.results = results
    
    def compose(self) -> ComposeResult:
        with Container(id="test-dialog"):
            yield Static("Connection Test Results", id="test-title")
            
            # IP test
            with Horizontal(classes="test-result-row"):
                yield Label("Public IP:", classes="test-result-label")
                yield Label(
                    self.results.get('public_ip', 'N/A'),
                    classes="test-result-value"
                )
            
            # IP leak
            with Horizontal(classes="test-result-row"):
                yield Label("IP Leak:", classes="test-result-label")
                leak_status = "PASS" if not self.results.get('ip_leak', True) else "FAIL"
                leak_class = "test-result-pass" if not self.results.get('ip_leak', True) else "test-result-fail"
                yield Label(leak_status, classes=leak_class)
            
            # DNS leak
            with Horizontal(classes="test-result-row"):
                yield Label("DNS Leak:", classes="test-result-label")
                dns_leak_status = "PASS" if not self.results.get('dns_leak', True) else "FAIL"
                dns_leak_class = "test-result-pass" if not self.results.get('dns_leak', True) else "test-result-fail"
                yield Label(dns_leak_status, classes=dns_leak_class)
            
            # Location
            with Horizontal(classes="test-result-row"):
                yield Label("Location:", classes="test-result-label")
                yield Label(
                    self.results.get('location', 'Unknown'),
                    classes="test-result-value"
                )
            
            # Latency
            with Horizontal(classes="test-result-row"):
                yield Label("Latency:", classes="test-result-label")
                latency = self.results.get('latency', 0)
                yield Label(
                    f"{latency:.1f}ms" if latency > 0 else "N/A",
                    classes="test-result-value"
                )
            
            with Horizontal(classes="test-buttons"):
                yield Button("Close", variant="primary", id="btn-close-test")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()


class AboutDialog(ModalScreen):
    """About dialog"""
    
    CSS = """
    #about-dialog {
        align: center middle;
        width: 50;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    
    #about-title {
        width: 100%;
        text-align: center;
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    
    .about-text {
        width: 100%;
        text-align: center;
        margin-bottom: 1;
    }
    
    .about-buttons {
        margin-top: 1;
        height: auto;
    }
    """
    
    def compose(self) -> ComposeResult:
        with Container(id="about-dialog"):
            yield Static("VPN Manager", id="about-title")
            yield Static("Advanced VPN Manager with Kill Switch", classes="about-text")
            yield Static("Version 1.0.0", classes="about-text")
            yield Static("", classes="about-text")
            yield Static("Terminal User Interface", classes="about-text")
            yield Static("Built with Textual", classes="about-text")
            yield Static("", classes="about-text")
            yield Static("Features:", classes="about-text")
            yield Static("- Advanced Kill Switch", classes="about-text")
            yield Static("- IP Rotation", classes="about-text")
            yield Static("- DNS Leak Protection", classes="about-text")
            yield Static("- OpenVPN Support", classes="about-text")
            
            with Horizontal(classes="about-buttons"):
                yield Button("Close", variant="primary", id="btn-close-about")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()
