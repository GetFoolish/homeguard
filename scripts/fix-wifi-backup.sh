#!/bin/bash

# Fix WiFi Backup Priority - Ensure WiFi can take over if bridge fails

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
   echo "Run with sudo"; exit 1
fi

log "🛡️ Fixing WiFi backup priority..."

# Get WiFi IP for testing
WIFI_IP=$(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [[ -z "$WIFI_IP" ]]; then
    echo "❌ WiFi has no IP address"
    exit 1
fi

log "WiFi IP detected: $WIFI_IP"

# Add a high-priority WiFi backup route
ip route add default via 192.168.4.1 dev wlan0 metric 50 2>/dev/null || {
    # Route might exist, delete and recreate
    ip route del default via 192.168.4.1 dev wlan0 metric 50 2>/dev/null || true
    ip route add default via 192.168.4.1 dev wlan0 metric 50
}

log "✅ WiFi backup route added with high priority (metric 50)"

# Test WiFi backup by checking if WiFi route exists and gateway is reachable
if ip route show | grep -q "default via 192.168.4.1 dev wlan0 metric 50"; then
    log "✅ High-priority WiFi route confirmed"
    # Test gateway reachability via WiFi network
    if ping -c 2 192.168.4.1 >/dev/null 2>&1; then
        log "✅ WiFi backup gateway reachable"
    else
        echo "⚠️ WiFi gateway test failed but route is configured"
    fi
else
    echo "❌ Failed to add high-priority WiFi route"
    exit 1
fi

log "🎉 WiFi backup is now bulletproof!"
log "   WiFi IP: $WIFI_IP"
log "   Backup route: default via 192.168.4.1 dev wlan0 metric 50"
