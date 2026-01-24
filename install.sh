#!/bin/bash
# VPN Manager Installation Script
set -e
VENV=".venv"
PY="$VENV/bin/python"

echo "Installing VPN Manager Python package..."

# Ensure python venv support exists
command -v python3 >/dev/null || {
    echo "python3 not found"
    exit 1
}

# Create venv if missing
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

# Upgrade pip INSIDE venv
"$PY" -m pip install --upgrade pip

# Install package
if [ -f setup.py ]; then
    "$PY" -m pip install -e .
elif [ -f requirements.txt ]; then
    "$PY" -m pip install -r requirements.txt
else
    echo "Error: No setup.py or requirements.txt found"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}VPN Manager Installation Script${NC}"
echo "=================================="
echo

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect distribution${NC}"
    exit 1
fi

echo "Detected: $DISTRO $VERSION"
echo
install_system() {
    echo -e "${GREEN}[SYSTEM] Installing system dependencies${NC}"

    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: --system must be run as root (use sudo)${NC}"
        exit 1
    fi
# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
case $DISTRO in
    ubuntu|debian)
        apt-get update
        apt-get install -y \
            python3 \
            python3-pip \
            python3-venv \
            openvpn \
            iptables \
            iproute2 \
            curl \
            wget
        ;;
    
    fedora|rhel|centos)
        dnf install -y \
            python3 \
            python3-pip \
            openvpn \
            iptables \
            iproute \
            curl \
            wget
        ;;
    
    arch|manjaro)
        pacman -Sy --noconfirm \
            python \
            python-pip \
            openvpn \
            iptables \
            iproute2 \
            curl \
            wget
        ;;
    
    *)
        echo -e "${YELLOW}Warning: Unsupported distribution${NC}"
        echo "Please install dependencies manually:"
        echo "  - Python 3.7+"
        echo "  - pip"
        echo "  - OpenVPN"
        echo "  - iptables"
        echo "  - iproute2"
        ;;
esac

echo -e "${GREEN}System dependencies installed${NC}"
echo

# Install Python package
echo -e "${YELLOW}Installing VPN Manager Python package...${NC}"

# Upgrade pip
python3 -m pip install --upgrade pip

# Install package
if [ -f "setup.py" ]; then
    # Development installation
    python3 -m pip install -e .
elif [ -f "requirements.txt" ]; then
    # Install from requirements
    python3 -m pip install -r requirements.txt
else
    echo -e "${RED}Error: No setup.py or requirements.txt found${NC}"
    exit 1
fi

echo -e "${GREEN}Python package installed${NC}"
echo

# Create directories
echo -e "${YELLOW}Creating configuration directories...${NC}"

# System config directory
mkdir -p /etc/vpn-manager/profiles
mkdir -p /etc/vpn-manager/scripts

# User config directory (for current user before sudo)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)

sudo -u $REAL_USER mkdir -p $REAL_HOME/.config/vpn-manager/profiles
sudo -u $REAL_USER mkdir -p $REAL_HOME/.config/vpn-manager/logs

echo -e "${GREEN}Directories created${NC}"
echo

# Copy default configuration
echo -e "${YELLOW}Setting up default configuration...${NC}"

if [ -f "config/settings.yaml" ]; then
    cp config/settings.yaml /etc/vpn-manager/
    sudo -u $REAL_USER cp config/settings.yaml $REAL_HOME/.config/vpn-manager/
    echo -e "${GREEN}Configuration files copied${NC}"
else
    echo -e "${YELLOW}Warning: Default configuration not found${NC}"
fi

echo

# Set up systemd service (optional)
read -p "Install systemd service for auto-connect? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/vpn-manager.service << 'EOF'
[Unit]
Description=VPN Manager Auto-Connect
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vpn-manager connect --profile /etc/vpn-manager/profiles/default.ovpn
ExecStop=/usr/local/bin/vpn-manager disconnect
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    echo -e "${GREEN}Systemd service created${NC}"
    echo "Note: Add default.ovpn to /etc/vpn-manager/profiles/ and enable service:"
    echo "  sudo systemctl enable vpn-manager"
    echo "  sudo systemctl start vpn-manager"
else
    echo "Skipping systemd service installation"
fi

echo

# Verify installation
echo -e "${YELLOW}Verifying installation...${NC}"

# Check if vpn-manager command is available
if command -v vpn-manager &> /dev/null; then
    echo -e "${GREEN}vpn-manager command: OK${NC}"
else
    echo -e "${RED}vpn-manager command: NOT FOUND${NC}"
    echo "You may need to add Python bin directory to PATH"
fi

# Check OpenVPN
if command -v openvpn &> /dev/null; then
    OPENVPN_VERSION=$(openvpn --version | head -1)
    echo -e "${GREEN}OpenVPN: $OPENVPN_VERSION${NC}"
else
    echo -e "${RED}OpenVPN: NOT FOUND${NC}"
fi

# Check iptables
if command -v iptables &> /dev/null; then
    echo -e "${GREEN}iptables: OK${NC}"
else
    echo -e "${RED}iptables: NOT FOUND${NC}"
fi

# Check Python version
PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}Python: $PYTHON_VERSION${NC}"

echo
echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Next steps:"
echo "1. Add your VPN profile to ~/.config/vpn-manager/profiles/"
echo "2. Edit configuration: nano ~/.config/vpn-manager/settings.yaml"
echo "3. Connect: sudo vpn-manager connect --profile your-profile.ovpn"
echo
echo "For help: vpn-manager --help"
echo "Documentation: README.md and USAGE.md"
}
