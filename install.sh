#!/usr/bin/env bash
# install.sh – build vpn-manager and install it
#
# Usage:
#   ./install.sh                 build + install to /usr/local/bin (asks sudo)
#   sudo ./install.sh            same
#   sudo ./install.sh --global-link   also symlink /usr/bin/vpn-manager
#
# Flags:
#   --system        install to /usr/local/bin (this is already the default)
#   --global-link   create /usr/bin/vpn-manager -> /usr/local/bin/vpn-manager
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="vpn-manager"
INSTALL_DIR="/usr/local/bin"
GLOBAL_LINK=0

for arg in "$@"; do
    case "$arg" in
        --system)      ;;  # default target, accepted for compatibility
        --global-link) GLOBAL_LINK=1 ;;
        *)
            echo "error: unknown flag: $arg" >&2
            echo "supported: --system, --global-link" >&2
            exit 1
            ;;
    esac
done

echo "==> building $BINARY (release)..."
cd "$SCRIPT_DIR"

# Never build as root — it litters target/ with root-owned files that break
# later user builds. If invoked via sudo, drop back to the invoking user.
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" cargo build --release
else
    cargo build --release
fi

BUILT="$SCRIPT_DIR/target/release/$BINARY"

SUDO=""
if [[ $EUID -ne 0 ]]; then
    echo "==> not root; installing to $INSTALL_DIR requires sudo:"
    SUDO="sudo"
fi

$SUDO install -m 755 -o root -g root "$BUILT" "$INSTALL_DIR/$BINARY"
echo "==> installed to $INSTALL_DIR/$BINARY"

if [[ $GLOBAL_LINK -eq 1 ]]; then
    $SUDO ln -sf "$INSTALL_DIR/$BINARY" "/usr/bin/$BINARY"
    echo "==> linked /usr/bin/$BINARY -> $INSTALL_DIR/$BINARY"
else
    # Clean up a stale/dangling symlink from an older install layout
    if [[ -L "/usr/bin/$BINARY" && ! -e "/usr/bin/$BINARY" ]]; then
        $SUDO rm -f "/usr/bin/$BINARY"
        echo "==> removed dangling symlink /usr/bin/$BINARY"
    fi
fi

echo ""
echo "Usage:"
echo "  sudo vpn-manager connect --config <file.ovpn>"
echo "  sudo vpn-manager connect --host <server> --port 1194 --proto udp"
echo "       vpn-manager list [dir]       # show configs in a folder"
echo "  sudo vpn-manager disconnect"
echo "  sudo vpn-manager recover      # emergency: restore network after a crash"
echo "       vpn-manager status"
