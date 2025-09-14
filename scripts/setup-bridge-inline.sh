#!/bin/bash

# HomeguardBridge Mode Setup - Bulletproof Inline Configuration
# Creates br0 bridge with eth0 + eth1 for transparent inline operation
# Preserves SSH/VNC access via dual management IPs (.100/.200)

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

log "🌉 Setting up HomeguardBridge Mode for Inline Deployment..."

# Network configuration
WAN_INTERFACE="eth0"      # ISP Router connection
LAN_INTERFACE="eth1"      # WiFi Mesh connection (USB ethernet)
BRIDGE_INTERFACE="br0"    # Bridge interface
CURRENT_NETWORK=""        # Will be auto-detected

# Verify interfaces exist
if [[ ! -d "/sys/class/net/$WAN_INTERFACE" ]]; then
    error "WAN interface $WAN_INTERFACE not found"
    exit 1
fi

if [[ ! -d "/sys/class/net/$LAN_INTERFACE" ]]; then
    error "LAN interface $LAN_INTERFACE not found"
    info "Available interfaces:"
    ls /sys/class/net/
    exit 1
fi

log "📋 Bridge Configuration:"
log "   • WAN Interface: $WAN_INTERFACE (ISP Router)"
log "   • LAN Interface: $LAN_INTERFACE (WiFi Mesh)"
log "   • Bridge Interface: $BRIDGE_INTERFACE"

# Detect current network environment
log "🔍 Auto-detecting network environment..."

# Get current gateway to determine network
CURRENT_GATEWAY=$(ip route show default | awk '{print $3}' | head -n1 || echo "")
if [[ -n "$CURRENT_GATEWAY" ]]; then
    CURRENT_NETWORK=$(echo "$CURRENT_GATEWAY" | cut -d. -f1-3)
    log "Detected network: $CURRENT_NETWORK.x (gateway: $CURRENT_GATEWAY)"
else
    # Default to common network if can't detect
    CURRENT_NETWORK="192.168.4"
    warn "Could not detect current network, using default: $CURRENT_NETWORK.x"
fi

# Set management IPs based on detected network
BRIDGE_IP_1="${CURRENT_NETWORK}.100"  # Primary management IP
BRIDGE_IP_2="${CURRENT_NETWORK}.200"  # Secondary management IP
GATEWAY_IP="$CURRENT_GATEWAY"

log "🔧 Management IPs:"
log "   • Primary: $BRIDGE_IP_1 (SSH/VNC)"
log "   • Secondary: $BRIDGE_IP_2 (Backup SSH/VNC)"
log "   • Gateway: $GATEWAY_IP"

# Create bridge interface
log "🌉 Creating bridge interface..."

# Remove bridge if it exists
if ip link show "$BRIDGE_INTERFACE" >/dev/null 2>&1; then
    warn "Bridge $BRIDGE_INTERFACE already exists, removing..."
    ip link set "$BRIDGE_INTERFACE" down 2>/dev/null || true
    brctl delbr "$BRIDGE_INTERFACE" 2>/dev/null || true
fi

# Install bridge utilities if needed
if ! command -v brctl >/dev/null 2>&1; then
    info "Installing bridge utilities..."
    apt-get update && apt-get install -y bridge-utils
fi

# Create new bridge
brctl addbr "$BRIDGE_INTERFACE"
brctl stp "$BRIDGE_INTERFACE" off  # Disable STP for performance

# Configure physical interfaces
log "🔌 Configuring physical interfaces..."

# Flush existing IPs from physical interfaces
ip addr flush dev "$WAN_INTERFACE" 2>/dev/null || true
ip addr flush dev "$LAN_INTERFACE" 2>/dev/null || true

# Bring up physical interfaces
ip link set "$WAN_INTERFACE" up
ip link set "$LAN_INTERFACE" up

# Add interfaces to bridge
brctl addif "$BRIDGE_INTERFACE" "$WAN_INTERFACE"
brctl addif "$BRIDGE_INTERFACE" "$LAN_INTERFACE"

# Configure bridge interface
log "🔧 Configuring bridge interface..."

# Bring up bridge
ip link set "$BRIDGE_INTERFACE" up

# Add management IPs to bridge
ip addr add "${BRIDGE_IP_1}/24" dev "$BRIDGE_INTERFACE"
ip addr add "${BRIDGE_IP_2}/24" dev "$BRIDGE_INTERFACE"

# Set default gateway
ip route add default via "$GATEWAY_IP" dev "$BRIDGE_INTERFACE" 2>/dev/null || true

# Enable IP forwarding
log "🔄 Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make IP forwarding persistent
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-homeguard-forwarding.conf

# Configure iptables for transparent forwarding
log "🛡️ Configuring iptables rules..."

# Clear existing rules
iptables -t nat -F 2>/dev/null || true
iptables -t filter -F FORWARD 2>/dev/null || true

# Allow all forwarding through bridge (transparent mode)
iptables -A FORWARD -i "$BRIDGE_INTERFACE" -o "$BRIDGE_INTERFACE" -j ACCEPT

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Preserve SSH and VNC access to management IPs
iptables -A INPUT -p tcp --dport 22 -d "$BRIDGE_IP_1" -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -d "$BRIDGE_IP_2" -j ACCEPT
iptables -A INPUT -p tcp --dport 5900 -d "$BRIDGE_IP_1" -j ACCEPT
iptables -A INPUT -p tcp --dport 5900 -d "$BRIDGE_IP_2" -j ACCEPT

# Allow web interface access
iptables -A INPUT -p tcp --dport 8080 -d "$BRIDGE_IP_1" -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -d "$BRIDGE_IP_2" -j ACCEPT

# Save iptables rules
info "💾 Saving iptables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Create persistent network configuration
log "📝 Creating persistent configuration..."

# Create systemd network files
mkdir -p /etc/systemd/network

# Bridge network configuration
cat > /etc/systemd/network/10-homeguard-bridge.netdev << EOF
# HomeguardBridge Interface
[NetDev]
Name=$BRIDGE_INTERFACE
Kind=bridge

[Bridge]
STP=false
ForwardDelaySec=0
HelloTimeSec=1
MaxAgeSec=10
EOF

cat > /etc/systemd/network/11-homeguard-bridge.network << EOF
# HomeguardBridge Network Configuration
[Match]
Name=$BRIDGE_INTERFACE

[Network]
IPForward=yes
Address=${BRIDGE_IP_1}/24
Address=${BRIDGE_IP_2}/24
Gateway=$GATEWAY_IP
DNS=8.8.8.8
DNS=8.8.4.4
EOF

# Bind physical interfaces to bridge
cat > /etc/systemd/network/20-homeguard-wan.network << EOF
# HomeguardWAN Interface (eth0) - Bridge Member
[Match]
Name=$WAN_INTERFACE

[Network]
Bridge=$BRIDGE_INTERFACE
IPForward=yes
EOF

cat > /etc/systemd/network/21-homeguard-lan.network << EOF
# HomeguardLAN Interface (eth1) - Bridge Member
[Match]
Name=$LAN_INTERFACE

[Network]
Bridge=$BRIDGE_INTERFACE
IPForward=yes
EOF

# Create configuration file for reference
mkdir -p /etc/homeguard
cat > /etc/homeguard/bridge.conf << EOF
# HomeguardBridge Configuration
BRIDGE_INTERFACE=$BRIDGE_INTERFACE
WAN_INTERFACE=$WAN_INTERFACE
LAN_INTERFACE=$LAN_INTERFACE
BRIDGE_IP_1=$BRIDGE_IP_1
BRIDGE_IP_2=$BRIDGE_IP_2
GATEWAY_IP=$GATEWAY_IP
NETWORK_BASE=$CURRENT_NETWORK
CONFIGURED_DATE=$(date)
EOF

# Enable systemd-networkd
systemctl enable systemd-networkd

# Test connectivity
log "🧪 Testing connectivity..."

# Test bridge interface
if ip addr show "$BRIDGE_INTERFACE" | grep -q "inet"; then
    info "✅ Bridge interface configured successfully"
    ip addr show "$BRIDGE_INTERFACE" | grep "inet"
else
    error "❌ Bridge interface configuration failed"
    exit 1
fi

# Test gateway connectivity
if ping -c 1 -W 3 "$GATEWAY_IP" >/dev/null 2>&1; then
    info "✅ Gateway connectivity verified: $GATEWAY_IP"
else
    warn "⚠️ Gateway ping failed - may work once fully deployed"
fi

log "🎉 Bridge Mode Setup Complete!"
echo ""
log "📊 Configuration Summary:"
log "   • Bridge Interface: $BRIDGE_INTERFACE"
log "   • Management IP 1: $BRIDGE_IP_1 (Primary SSH/VNC)"
log "   • Management IP 2: $BRIDGE_IP_2 (Secondary SSH/VNC)"
log "   • Gateway: $GATEWAY_IP"
log "   • Physical Interfaces: $WAN_INTERFACE + $LAN_INTERFACE"
echo ""
log "🔗 Access Points:"
log "   • SSH Primary: ssh raspberrypi@$BRIDGE_IP_1"
log "   • SSH Secondary: ssh raspberrypi@$BRIDGE_IP_2"
log "   • VNC Primary: $BRIDGE_IP_1:5900"
log "   • VNC Secondary: $BRIDGE_IP_2:5900"
log "   • Web Admin: http://$BRIDGE_IP_1:8080"
echo ""
log "🚀 Ready for Inline Deployment!"
log "   Physical Connection: ISP Router → Pi $WAN_INTERFACE → Bridge → Pi $LAN_INTERFACE → WiFi Mesh"
echo ""
warn "⚠️ NEXT STEPS:"
warn "   1. Test SSH access via both IPs in current position"
warn "   2. Verify internet works through bridge"
warn "   3. Only then move Pi to inline position"

# Create recovery script
cat > /usr/local/bin/homeguard-bridge-recovery << 'EOF'
#!/bin/bash
# HomeguardBridge Recovery Script
echo "Removing bridge configuration..."
ip link set br0 down 2>/dev/null || true
brctl delbr br0 2>/dev/null || true

echo "Restoring eth0 DHCP..."
dhclient -r eth0 2>/dev/null || true
dhclient eth0

echo "Bridge removed, eth0 restored to DHCP"
echo "SSH should be accessible via original IP"
EOF

chmod +x /usr/local/bin/homeguard-bridge-recovery

log "🆘 Recovery command available: homeguard-bridge-recovery"