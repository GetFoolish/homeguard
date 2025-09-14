#!/bin/bash

# HomeguardSafe Router Mode Setup
# Converts Pi from bridge mode to router mode safely
# Maintains connectivity throughout process with automatic rollback

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

# Safety check function
test_connectivity() {
    local test_name="$1"
    info "Testing connectivity: $test_name"

    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log "✅ Internet connectivity: OK"
        return 0
    else
        error "❌ Internet connectivity: FAILED"
        return 1
    fi
}

# Rollback function
rollback() {
    error "🔄 ROLLBACK INITIATED - Restoring previous configuration..."

    # Restore bridge if it existed
    if [[ -f "/tmp/homeguard_bridge_backup" ]]; then
        info "Restoring bridge configuration..."
        source /tmp/homeguard_bridge_backup

        # Recreate bridge
        brctl addbr br0 2>/dev/null || true
        brctl addif br0 eth0 2>/dev/null || true
        brctl addif br0 eth1 2>/dev/null || true
        ip link set br0 up
        ip addr add 192.168.4.100/24 dev br0 2>/dev/null || true
        ip addr add 192.168.4.200/24 dev br0 2>/dev/null || true
        ip route add default via 192.168.4.1 dev br0 2>/dev/null || true
    fi

    warn "Rollback completed. Please test connectivity."
    exit 1
}

# Trap to catch errors and rollback
trap 'rollback' ERR

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "🛡️ HomeguardSafe Router Mode Setup Starting..."

# Pre-flight checks
info "🔍 Pre-flight connectivity check..."
if ! test_connectivity "Initial"; then
    error "No internet connectivity detected. Please fix connectivity first."
    exit 1
fi

# Backup current configuration
info "💾 Backing up current network configuration..."
ip addr > /tmp/homeguard_network_backup.txt
ip route > /tmp/homeguard_route_backup.txt
brctl show > /tmp/homeguard_bridge_backup.txt 2>/dev/null || true

# Save bridge state if it exists
if ip link show br0 >/dev/null 2>&1; then
    echo "BRIDGE_EXISTS=true" > /tmp/homeguard_bridge_backup
    echo "BRIDGE_IPS=\"$(ip addr show br0 | grep 'inet ' | awk '{print $2}')\"" >> /tmp/homeguard_bridge_backup
else
    echo "BRIDGE_EXISTS=false" > /tmp/homeguard_bridge_backup
fi

log "📋 Router Mode Configuration Plan:"
log "   • WAN Interface: eth0 (will connect to ISP)"
log "   • LAN Interface: eth1 (will connect to WiFi router)"
log "   • Management: Available via both WAN and LAN sides"
log "   • WiFi Backup: Maintained throughout process"

# Step 1: Prepare interfaces
info "🔧 Step 1: Preparing network interfaces..."

# Remove existing bridge configuration gradually
if ip link show br0 >/dev/null 2>&1; then
    info "Removing bridge configuration..."

    # Remove IPs from bridge but keep it up for now
    ip addr flush dev br0 2>/dev/null || true

    # Test connectivity via WiFi backup
    if ! test_connectivity "After bridge IP flush"; then
        error "Lost connectivity after bridge flush - checking WiFi backup..."
        if ! ping -c 1 -W 3 -I wlan0 8.8.8.8 >/dev/null 2>&1; then
            error "WiFi backup also failed!"
            rollback
        fi
        warn "Bridge connectivity lost but WiFi backup working"
    fi
fi

# Step 2: Configure WAN interface (eth0)
info "🌐 Step 2: Configuring WAN interface (eth0)..."

# For now, in sideline mode, eth0 gets DHCP from current network
nmcli connection modify "Wired connection 1" ipv4.method auto 2>/dev/null || {
    # Create connection if it doesn't exist
    nmcli connection add type ethernet ifname eth0 con-name "HomeguardWAN" 2>/dev/null || true
}

# Step 3: Configure LAN interface (eth1)
info "🏠 Step 3: Configuring LAN interface (eth1)..."

# eth1 will serve the WiFi router - give it an IP in 192.168.4.x range for now
nmcli connection add type ethernet ifname eth1 con-name "HomeguardLAN" \
    ipv4.method manual \
    ipv4.addresses 192.168.4.100/24 \
    ipv4.gateway 192.168.4.1 \
    ipv4.dns "8.8.8.8,8.8.4.4" \
    connection.autoconnect yes 2>/dev/null || {
    # Modify if exists
    nmcli connection modify eth1 \
        ipv4.method manual \
        ipv4.addresses 192.168.4.100/24 \
        ipv4.gateway 192.168.4.1 \
        ipv4.dns "8.8.8.8,8.8.4.4" 2>/dev/null || true
}

# Step 4: Enable IP forwarding
info "🔄 Step 4: Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-homeguard-router.conf

# Step 5: Configure NAT rules
info "🛡️ Step 5: Configuring NAT iptables rules..."

# Clear existing rules
iptables -t nat -F 2>/dev/null || true
iptables -t filter -F FORWARD 2>/dev/null || true

# Enable NAT from LAN to WAN
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Allow traffic forwarding
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow management access
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH
iptables -A INPUT -p tcp --dport 5900 -j ACCEPT  # VNC
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT  # Web interface

# Save iptables rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Step 6: Remove old bridge if everything is working
info "🧹 Step 6: Cleaning up old bridge configuration..."

if ip link show br0 >/dev/null 2>&1; then
    # Test connectivity before removing bridge
    if test_connectivity "Before bridge removal"; then
        info "Removing bridge interface..."
        ip link set br0 down 2>/dev/null || true
        brctl delbr br0 2>/dev/null || true
    else
        warn "Connectivity issues detected - keeping bridge as backup"
    fi
fi

# Step 7: Final connectivity test
info "🧪 Step 7: Final connectivity validation..."

if test_connectivity "Final validation"; then
    log "✅ Router mode setup completed successfully!"
else
    error "Final connectivity test failed"
    rollback
fi

# Create configuration summary
log "📊 Router Mode Configuration Summary:"
log "   • WAN Interface (eth0): $(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | head -n1)"
log "   • LAN Interface (eth1): $(ip addr show eth1 | grep 'inet ' | awk '{print $2}' | head -n1)"
log "   • WiFi Backup: $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | head -n1)"
log "   • IP Forwarding: Enabled"
log "   • NAT Rules: Configured"

echo ""
log "🔗 Management Access:"
log "   • SSH via WAN: ssh raspberrypi@$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
log "   • SSH via LAN: ssh raspberrypi@$(ip addr show eth1 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
log "   • SSH via WiFi: ssh raspberrypi@$(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"

echo ""
log "🚀 Ready for Inline Deployment Test!"
warn "⚠️ Current Status: SIDELINE MODE - Traffic not flowing through Pi yet"
warn "⚠️ To test inline: Connect eth1 to WiFi router WAN port (temporarily)"
warn "⚠️ Full inline: Move ISP connection from router to Pi eth0"

# Clean up temporary files
rm -f /tmp/homeguard_bridge_backup /tmp/homeguard_network_backup.txt /tmp/homeguard_route_backup.txt /tmp/homeguard_bridge_backup.txt

log "✅ Router mode setup completed successfully!"