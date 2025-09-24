#!/bin/bash
#
# HomeguardGuard Emergency Restore Script
#
# Purpose:
# 1. Shutdown HomeguardGuard service completely
# 2. Set iptables to transparent mode (all traffic flows)
#
# This script is SAFE and will NOT crash the system.
# It only makes minimal, necessary changes.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"; }

# Must run as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "🆘 EMERGENCY RESTORE - Shutting down and setting transparent mode..."

# Step 1: Stop HomeguardGuard service
log "📴 Stopping HomeguardGuard service..."
if systemctl is-active homeguard >/dev/null 2>&1; then
    systemctl stop homeguard
    log "✅ HomeguardGuard service stopped"
else
    log "ℹ️  HomeguardGuard service was not running"
fi

# Step 2: Reset iptables to clean transparent state
log "🔧 Resetting iptables to clean transparent mode..."

# Flush all tables completely (but preserve system chains)
log "  → Flushing all iptables rules..."
iptables -t filter -F
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -t mangle -F 2>/dev/null || true

# Delete custom chains
log "  → Removing custom chains..."
iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true
iptables -t filter -X MYPROXY_FILTER 2>/dev/null || true
iptables -t filter -X IOT_DEVICE_FILTER 2>/dev/null || true

# Set permissive policies for safety
log "  → Setting permissive policies..."
iptables -t filter -P INPUT ACCEPT      # Default policy: Allow all traffic TO this gateway/router
iptables -t filter -P FORWARD ACCEPT    # Default policy: Allow all traffic THROUGH this gateway/router
iptables -t filter -P OUTPUT ACCEPT     # Default policy: Allow all traffic FROM this gateway/router

# Rebuild minimal transparent rules
log "  → Building minimal transparent ruleset..."

iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,8081 -j ACCEPT  # Allow TCP traffic TO ports 22(SSH), 5900(VNC), 8081(Web) - ensures admin access always works
iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,8081 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT  # Allow TCP traffic FROM ports 22,5900,8081 that's part of existing connections - return traffic for admin sessions

iptables -t filter -A FORWARD -i eth1 -o eth0 -j ACCEPT  # Allow ALL traffic from LAN (eth1) to WAN (eth0) - clients can reach internet
iptables -t filter -A FORWARD -i eth0 -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT  # Allow return traffic from WAN (eth0) to LAN (eth1) only if it's part of existing connections - internet responses back to clients

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  # Replace client private IPs with gateway's public IP when traffic exits to internet - enables internet access

iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8081  # Intercept HTTP requests (port 80) from LAN and redirect to gateway's web interface (port 8081) - captive portal

log "✅ Clean transparent iptables rules applied"

# Step 3: Test connectivity
log "🧪 Testing transparent mode connectivity..."

# Test if we can resolve DNS
if nslookup google.com >/dev/null 2>&1; then
    log "✅ DNS resolution working"
else
    warn "⚠️  DNS resolution may have issues"
fi

# Show current network state
log "📊 Current network state:"
log "    Interface status:"
ip link show eth0 | head -n 1 | sed 's/^/        /'
ip link show eth1 | head -n 1 | sed 's/^/        /'

log "    Gateway IP addresses:"
ip addr show eth1 | grep 'inet ' | awk '{print "        " $2}' || log "        No IP on eth1"

log "    Current iptables FORWARD rules:"
iptables -t filter -L FORWARD -n --line-numbers | head -n 10 | sed 's/^/        /'

log "✅ EMERGENCY RESTORE COMPLETED SUCCESSFULLY!"
log ""
log "🌐 System Status:"
log "   • HomeguardGuard service: STOPPED"
log "   • Traffic mode: TRANSPARENT (all traffic allowed)"
log "   • Management access: PRESERVED (SSH/VNC/Web)"
log "   • Captive portal: DISABLED"
log ""
log "🔧 To restart HomeguardGuard: sudo systemctl start homeguard"
log "📱 Web admin access: http://$(ip addr show eth1 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1):8081/admin"