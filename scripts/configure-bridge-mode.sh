#!/bin/bash

# MyProxy Bridge Mode Configuration Script
# Sets up Pi for inline deployment between ISP router and WiFi router

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "🌉 Configuring MyProxy Bridge Mode..."

# Load configuration
if [[ -f "/etc/myproxy/mode.conf" ]]; then
    source /etc/myproxy/mode.conf
    info "Loaded configuration from /etc/myproxy/mode.conf"
else
    warn "No mode configuration found, using defaults"
    WAN_INTERFACE="eth0"
    LAN_INTERFACE="auto"
fi

# Auto-detect USB ethernet if needed
if [[ "$LAN_INTERFACE" == "auto" ]]; then
    log "🔍 Auto-detecting USB ethernet interface..."
    
    # Run USB ethernet detection
    if [[ -f "$SCRIPT_DIR/detect-usb-ethernet.sh" ]]; then
        bash "$SCRIPT_DIR/detect-usb-ethernet.sh"
        source /etc/myproxy/mode.conf  # Reload updated config
    else
        error "USB ethernet detection script not found"
        exit 1
    fi
fi

log "📋 Bridge Configuration:"
log "   • WAN Interface: $WAN_INTERFACE (ISP Router)"
log "   • LAN Interface: $LAN_INTERFACE (WiFi Router)"
log "   • Mode: Bridge (transparent inline)"

# Verify interfaces exist
if [[ ! -d "/sys/class/net/$WAN_INTERFACE" ]]; then
    error "WAN interface $WAN_INTERFACE not found"
    exit 1
fi

if [[ ! -d "/sys/class/net/$LAN_INTERFACE" ]]; then
    error "LAN interface $LAN_INTERFACE not found"
    ls /sys/class/net/
    exit 1
fi

# Configure network interfaces
log "🔧 Configuring network interfaces..."

# Bring up interfaces
info "Bringing up network interfaces..."
ip link set $WAN_INTERFACE up
ip link set $LAN_INTERFACE up

# Configure WAN interface (DHCP from ISP)
info "Configuring WAN interface ($WAN_INTERFACE) for DHCP..."
dhclient -r $WAN_INTERFACE 2>/dev/null || true
dhclient $WAN_INTERFACE

# Configure LAN interface (no IP - bridge mode)
info "Configuring LAN interface ($LAN_INTERFACE) for bridge mode..."
ip addr flush dev $LAN_INTERFACE 2>/dev/null || true

# Enable IP forwarding
log "🔄 Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make IP forwarding persistent
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-myproxy-forwarding.conf

# Set up bridge networking
log "🌉 Setting up bridge networking..."

# Clear existing iptables rules
iptables -t nat -F POSTROUTING 2>/dev/null || true
iptables -t filter -F FORWARD 2>/dev/null || true

# Set up NAT for outgoing traffic
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow traffic from LAN to WAN (will be filtered by MyProxy)
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT

# Allow traffic from WAN to LAN (return traffic)
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT

# Save iptables rules
info "💾 Saving iptables rules..."
iptables-save > /etc/iptables/rules.v4

# Create network configuration file
log "📝 Creating persistent network configuration..."

cat > /etc/systemd/network/10-myproxy-bridge.network << EOF
# MyProxy Bridge Mode Network Configuration
[Match]
Name=$WAN_INTERFACE

[Network]
DHCP=yes
IPForward=yes

[DHCP]
UseDNS=yes
UseRoutes=yes
EOF

cat > /etc/systemd/network/20-myproxy-lan.network << EOF
# MyProxy LAN Interface Configuration  
[Match]
Name=$LAN_INTERFACE

[Network]
IPForward=yes
# No IP configuration - bridge mode
EOF

# Enable systemd-networkd if not already enabled
systemctl enable systemd-networkd

# Configure environment for MyProxy containers
log "🐳 Configuring Docker environment..."

# Update MyProxy environment
cat > /etc/myproxy/bridge.env << EOF
# MyProxy Bridge Mode Environment Variables
MYPROXY_MODE=bridge
WAN_INTERFACE=$WAN_INTERFACE
LAN_INTERFACE=$LAN_INTERFACE
MYPROXY_GATEWAY_IP=auto
MYPROXY_WEB_HOST=0.0.0.0
MYPROXY_WEB_PORT=8080
MYPROXY_DATABASE_URL=sqlite+aiosqlite:////app/data/myproxy.db
MYPROXY_AUTO_RECOVERY=true
MYPROXY_LOG_LEVEL=INFO
EOF

# Update systemd service to use bridge environment
mkdir -p /etc/systemd/system/myproxy-dual.service.d
cat > /etc/systemd/system/myproxy-dual.service.d/bridge.conf << EOF
[Service]
EnvironmentFile=/etc/myproxy/bridge.env
EOF

# Reload systemd configuration
systemctl daemon-reload

log "✅ Bridge mode configuration complete!"
echo ""
log "📊 Configuration Summary:"
log "   • IP Forwarding: Enabled"
log "   • NAT: $WAN_INTERFACE → Internet"
log "   • Bridge: $LAN_INTERFACE ↔ $WAN_INTERFACE"
log "   • MyProxy: Will filter all FORWARD traffic"
echo ""
log "🔗 Physical Connection Required:"
log "   ISP Router → Pi $WAN_INTERFACE → Pi $LAN_INTERFACE → WiFi Router WAN"
echo ""
log "🚀 Ready for inline deployment!"
log "   Start MyProxy: systemctl restart myproxy-dual"
log "   Check status: systemctl status myproxy-dual"
log "   View logs: journalctl -u myproxy-dual -f"