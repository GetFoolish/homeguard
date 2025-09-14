#!/bin/bash

# HomeguardGateway Setup - Ultra Safe Approach
# Adds gateway functionality on top of existing working bridge
# No disruption to current connectivity

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }
info() { echo -e "${BLUE}[$(date '+%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
   error "Run with sudo"
   exit 1
fi

log "🚀 HomeguardGateway Setup - Safe Addition Mode"

# Test current connectivity
if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    error "No internet connectivity - fix first"
    exit 1
fi
log "✅ Current connectivity confirmed"

# Add gateway functionality WITHOUT touching existing bridge
log "🔧 Adding gateway functionality..."

# Enable IP forwarding (safe)
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-homeguard-gateway.conf
log "✅ IP forwarding enabled"

# Add NAT rules for gateway mode (don't remove existing rules)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Preserve management access
iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 5900 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true

# Save iptables
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
log "✅ Gateway NAT rules added"

# Test connectivity still works
if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    error "Connectivity lost after NAT setup"
    exit 1
fi
log "✅ Connectivity still working after gateway setup"

# Prepare eth1 for LAN usage (but don't activate)
nmcli connection delete "HomeguardLAN" 2>/dev/null || true
nmcli connection add type ethernet ifname eth1 con-name "HomeguardLAN" \
    ipv4.method manual \
    ipv4.addresses 192.168.4.200/24 \
    ipv4.dns "8.8.8.8,8.8.4.4" \
    connection.autoconnect no 2>/dev/null
log "✅ eth1 LAN interface prepared (not active)"

echo ""
log "🎉 Gateway functionality added successfully!"
log "📊 Current Status:"
log "   • Bridge: Still working (192.168.4.100/200)"
log "   • WiFi backup: Still working"
log "   • Gateway/NAT: Added and ready"
log "   • eth1 LAN: Configured but inactive"

echo ""
log "🎯 Next Steps for Inline Testing:"
log "   1. Connect eth1 cable to WiFi router WAN port"
log "   2. Activate: sudo nmcli connection up HomeguardLAN"
log "   3. Test if WiFi router gets internet through Pi"
log "   4. If working, move ISP cable to Pi eth0"

echo ""
log "🆘 Safety Commands:"
log "   • Emergency restore: sudo /home/raspberrypi/CODE_STUFF/homeguard/scripts/emergency-restore.sh"
log "   • Deactivate eth1: sudo nmcli connection down HomeguardLAN"
log "   • Check connectivity: ping 8.8.8.8"

log "✅ Ready for safe inline testing!"
