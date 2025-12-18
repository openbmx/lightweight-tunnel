#!/bin/bash
# Lightweight Tunnel Verification Script
# This script helps verify that the tunnel and P2P connections are working

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "Lightweight Tunnel Verification Script"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

echo -e "${GREEN}✓${NC} Running as root"

# Check for /dev/net/tun
echo ""
echo "=== Checking TUN device ==="
if [ ! -c /dev/net/tun ]; then
    echo -e "${RED}✗${NC} /dev/net/tun not found"
    echo "Attempting to load tun module..."
    modprobe tun 2>/dev/null || {
        echo -e "${RED}ERROR: Cannot load tun module${NC}"
        exit 1
    }
fi

if [ -c /dev/net/tun ]; then
    echo -e "${GREEN}✓${NC} /dev/net/tun exists and is accessible"
else
    echo -e "${RED}✗${NC} /dev/net/tun still not available"
    exit 1
fi

# Check if binary exists
echo ""
echo "=== Checking binary ==="
if [ -f "./lightweight-tunnel" ]; then
    echo -e "${GREEN}✓${NC} Binary found: ./lightweight-tunnel"
elif [ -f "./cmd/lightweight-tunnel/lightweight-tunnel" ]; then
    echo -e "${GREEN}✓${NC} Binary found: ./cmd/lightweight-tunnel/lightweight-tunnel"
    cd cmd/lightweight-tunnel
else
    echo -e "${YELLOW}!${NC} Binary not found. Attempting to build..."
    if command -v go &> /dev/null; then
        go build -o lightweight-tunnel ./cmd/lightweight-tunnel
        echo -e "${GREEN}✓${NC} Built binary successfully"
    else
        echo -e "${RED}✗${NC} Go compiler not found. Please build the binary first:"
        echo "  go build -o lightweight-tunnel ./cmd/lightweight-tunnel"
        exit 1
    fi
fi

# Check binary can be executed
if ./lightweight-tunnel -v &> /dev/null; then
    VERSION=$(./lightweight-tunnel -v 2>&1)
    echo -e "${GREEN}✓${NC} Binary is executable: $VERSION"
else
    echo -e "${RED}✗${NC} Binary cannot be executed"
    exit 1
fi

# Test TUN device creation
echo ""
echo "=== Testing TUN device creation ==="
TEMP_TUN="verify_test_tun"

# Try to create a test TUN with ip tuntap
if ip tuntap add mode tun name $TEMP_TUN 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Successfully created test TUN device: $TEMP_TUN"
    
    # Configure it
    if ip addr add 192.168.99.1/24 dev $TEMP_TUN 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Successfully configured test TUN device"
    else
        echo -e "${YELLOW}!${NC} Could not configure test TUN device (non-critical)"
    fi
    
    # Bring it up
    if ip link set $TEMP_TUN up 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Successfully brought up test TUN device"
    else
        echo -e "${YELLOW}!${NC} Could not bring up test TUN device (non-critical)"
    fi
    
    # Clean up
    ip link delete $TEMP_TUN 2>/dev/null
    echo -e "${GREEN}✓${NC} Cleaned up test TUN device"
else
    echo -e "${YELLOW}!${NC} Could not create test TUN device with ip tuntap"
    echo "   This might be OK - the application uses a different method"
fi

# Check for existing tunnel processes
echo ""
echo "=== Checking for existing tunnel processes ==="
if pgrep -f lightweight-tunnel > /dev/null; then
    echo -e "${YELLOW}!${NC} Found existing lightweight-tunnel processes:"
    pgrep -fa lightweight-tunnel | sed 's/^/    /'
    echo ""
    echo "You may want to stop these before starting new instances:"
    echo "  sudo pkill -f lightweight-tunnel"
else
    echo -e "${GREEN}✓${NC} No existing tunnel processes found"
fi

# Check for port conflicts
echo ""
echo "=== Checking for port availability ==="
DEFAULT_PORT=9000
if netstat -tuln 2>/dev/null | grep -q ":$DEFAULT_PORT " || ss -tuln 2>/dev/null | grep -q ":$DEFAULT_PORT "; then
    echo -e "${YELLOW}!${NC} Port $DEFAULT_PORT is already in use"
    echo "   You may need to use a different port or stop the conflicting service"
else
    echo -e "${GREEN}✓${NC} Default port $DEFAULT_PORT is available"
fi

# Summary
echo ""
echo "============================================"
echo "Verification Summary"
echo "============================================"
echo ""
echo "Prerequisites:"
echo -e "  ${GREEN}✓${NC} Running as root"
echo -e "  ${GREEN}✓${NC} /dev/net/tun available"
echo -e "  ${GREEN}✓${NC} Binary is executable"
echo ""
echo "Ready to test the tunnel!"
echo ""
echo "Next steps:"
echo ""
echo "1. Start server (in one terminal):"
echo "   sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 -k \"test-key\""
echo ""
echo "2. Start client (in another terminal):"
echo "   sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -k \"test-key\" -p2p"
echo ""
echo "3. Test connectivity:"
echo "   ping 10.0.0.1  # From client, ping server"
echo "   ping 10.0.0.2  # From server, ping client"
echo ""
echo "4. Watch for these log messages:"
echo "   - 'Created TUN device: tun0'"
echo "   - 'Configured tun0 with IP ...'"
echo "   - 'Received public address from server' (client only)"
echo "   - 'P2P connection established' (if P2P enabled)"
echo ""
echo "If you see 'TUN read error' or immediate failures:"
echo "  - Check that you're running as root"
echo "  - Check that TUN module is loaded: lsmod | grep tun"
echo "  - Check kernel config: grep TUN /boot/config-\$(uname -r)"
echo ""
