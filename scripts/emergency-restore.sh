#!/bin/bash

# Emergency Recovery Script - FIXED VERSION
# Preserves WiFi backup throughout recovery

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
   echo "Run with sudo"; exit 1
fi

log "🆘 EMERGENCY RECOVERY - Restoring working state..."

# DO NOT stop NetworkManager - it kills WiFi backup!
# systemctl stop NetworkManager  # REMOVED - this was the bug!

# Test WiFi backup first
if ping -c 1 -I wlan0 8.8.8.8 >/dev/null 2>&1; then
    log "✅ WiFi backup is working"
else
    warn "⚠️ WiFi backup not responding - enabling high priority route"
    ip route add default via 192.168.4.1 dev wlan0 metric 50 2>/dev/null || true
fi

# Fix bridge configuration
if ! ip link show br0 >/dev/null 2>&1; then
    log "Creating bridge..."
    brctl addbr br0 2>/dev/null || true
    brctl stp br0 off
fi

# Add interfaces to bridge if missing
brctl addif br0 eth0 2>/dev/null || true
brctl addif br0 eth1 2>/dev/null || true

# Configure bridge
ip link set eth0 up 2>/dev/null || true
ip link set eth1 up 2>/dev/null || true
ip link set br0 up

# Add bridge IPs if missing
ip addr add 192.168.4.100/24 dev br0 2>/dev/null || true
ip addr add 192.168.4.200/24 dev br0 2>/dev/null || true

# Add bridge default route with high priority
ip route add default via 192.168.4.1 dev br0 metric 10 2>/dev/null || true

# Clear any conflicting iptables
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true

log "🧪 Testing connectivity..."
if ping -c 2 8.8.8.8 >/dev/null 2>&1; then
    log "✅ RECOVERY SUCCESSFUL"
    log "   Bridge IPs: 192.168.4.100 + 192.168.4.200"
    log "   WiFi backup: $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | head -n1)"
    log "   SSH: ssh raspberrypi@192.168.4.100"
else
    warn "⚠️ Bridge failed, using WiFi backup only"
    log "   SSH: ssh raspberrypi@$(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
fi

log "🎉 Emergency recovery completed!"
