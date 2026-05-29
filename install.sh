#!/usr/bin/env bash
# install.sh – build vpn-manager and install to /usr/local/bin
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="vpn-manager"
INSTALL_DIR="/usr/local/bin"

echo "==> building $BINARY (release)..."
cd "$SCRIPT_DIR"
cargo build --release

BUILT="$SCRIPT_DIR/target/release/$BINARY"

if [[ $EUID -eq 0 ]]; then
    install -m 755 "$BUILT" "$INSTALL_DIR/$BINARY"
    echo "==> installed to $INSTALL_DIR/$BINARY"
else
    echo "==> not root; copying to $INSTALL_DIR requires sudo:"
    sudo install -m 755 "$BUILT" "$INSTALL_DIR/$BINARY"
    echo "==> installed to $INSTALL_DIR/$BINARY"
fi

# Set sticky-root permissions so it can be run as:
#   sudo vpn-manager connect ...
# (openvpn and iptables calls require root anyway)
sudo chown root:root "$INSTALL_DIR/$BINARY"
sudo chmod 755       "$INSTALL_DIR/$BINARY"

echo ""
echo "Usage:"
echo "  sudo vpn-manager connect --config <file.ovpn>"
echo "  sudo vpn-manager connect --host <server> --port 1194 --proto udp"
echo "  sudo vpn-manager disconnect"
echo "  sudo vpn-manager recover      # emergency: restore network after a crash"
echo "       vpn-manager status"
