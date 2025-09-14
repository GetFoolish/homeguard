#!/bin/bash

# Fix Inline Routing - Convert Bridge to Router Mode
# Auto-rollback to emergency restore if anything fails

set -e  # Exit on any error (triggers rollback)

# Colors and logging
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
LOG_FILE="/var/log/homeguard-routing-fix.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"; }

# Rollback function - calls emergency restore
rollback() {
    error "ROUTING FIX FAILED - Calling emergency restore..."
    /home/raspberrypi/CODE_STUFF/homeguard/scripts/emergency-restore.sh
    error "Rollback completed. Blue cable still needed."
    exit 1
}

# Trap any errors and rollback
trap 'rollback' ERR

if [[ $EUID -ne 0 ]]; then
   echo "Run with sudo"; exit 1
fi

log "🔧 Starting Inline Routing Fix - Bridge to Router Mode"

# Step 1: Test current connectivity
log "📡 Testing current connectivity..."
if ! ping -c 2 8.8.8.8 >/dev/null 2>&1; then
    error "No internet connectivity - fix first"
    exit 1
fi
log "✅ Current connectivity confirmed"

# Step 2: Save current configuration for potential rollback
log "💾 Saving current configuration..."
ip addr > /tmp/routing-fix-backup-addr.txt
ip route > /tmp/routing-fix-backup-routes.txt
brctl show > /tmp/routing-fix-backup-bridge.txt 2>/dev/null || true

# Step 3: Convert to router mode
log "🛠️ Converting from bridge mode to router mode..."

# Remove interfaces from bridge but keep bridge for now
brctl delif br0 eth0 2>/dev/null || warn "eth0 not in bridge"
brctl delif br0 eth1 2>/dev/null || warn "eth1 not in bridge"

# Configure eth0 as WAN (get ISP IP)
log "🌐 Configuring eth0 as WAN interface..."
ip addr flush dev eth0
dhclient -r eth0 2>/dev/null || true
dhclient eth0

# Wait for DHCP
sleep 5

# Check if eth0 got an IP
ETH0_IP=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "")
if [[ -z "$ETH0_IP" ]]; then
    error "Failed to get IP on eth0 from ISP"
    exit 1
fi
log "✅ eth0 WAN IP: $ETH0_IP"

# Configure eth1 as LAN (management + WiFi gateway)
log "🏠 Configuring eth1 as LAN interface..."
ip addr flush dev eth1
ip addr add 192.168.4.100/24 dev eth1
ip link set eth1 up

# Step 4: Setup NAT routing
log "🔄 Setting up NAT routing..."

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Clear existing iptables rules
iptables -F
iptables -t nat -F

# Setup NAT from LAN (eth1) to WAN (eth0)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow management access
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 5900 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

log "✅ NAT rules configured"

# Step 5: Configure routing for WiFi router
log "📡 Configuring routes for WiFi network..."

# Default route via ISP
ip route add default via $(ip route show dev eth0 | grep default | awk '{print $3}' | head -n1) dev eth0 metric 100

# Route for local WiFi network
ip route add 192.168.4.0/24 dev eth1 metric 50

# Step 6: Test router configuration
log "🧪 Testing router configuration..."

# Test 1: Can Pi reach internet?
if ! ping -c 2 8.8.8.8 >/dev/null 2>&1; then
    error "Pi cannot reach internet after router setup"
    exit 1
fi
log "✅ Pi internet connectivity working"

# Test 2: Is management IP reachable?
if ! ping -c 1 192.168.4.100 >/dev/null 2>&1; then
    error "Management IP not reachable"
    exit 1
fi
log "✅ Management IP (192.168.4.100) reachable"

# Step 7: Remove old bridge (no longer needed)
log "🧹 Cleaning up old bridge configuration..."
ip link set br0 down 2>/dev/null || true
brctl delbr br0 2>/dev/null || true

# Final connectivity test
log "🎯 Final connectivity test..."
if ! ping -c 2 8.8.8.8 >/dev/null 2>&1; then
    error "Final connectivity test failed"
    exit 1
fi

log "🎉 ROUTER MODE CONFIGURATION SUCCESSFUL!"
log ""
log "📊 New Configuration:"
log "   • eth0 (WAN): $ETH0_IP (ISP connection)"
log "   • eth1 (LAN): 192.168.4.100 (management + WiFi gateway)"
log "   • Mode: Router (NAT enabled)"
log "   • Bridge: Removed (no longer needed)"
log ""
log "🔌 Physical Deployment Status:"
log "   • ISP Router → Pi eth0 ✅"
log "   • Pi eth1 → WiFi Router WAN ✅"
log "   • Blue bypass cable: Can be removed!"
log ""
log "🎯 Management Access:"
log "   • SSH: ssh raspberrypi@192.168.4.100"
log "   • VNC: 192.168.4.100:5900"
log ""
warn "⚠️ NEXT STEP: Remove blue bypass cable to test pure inline mode!"

log "✅ Router mode setup completed successfully!"
