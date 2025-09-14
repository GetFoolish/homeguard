#!/bin/bash
# Quick network status check for MyProxy

echo "=== MyProxy Network Status ==="

# Check if network status file exists
if [ -f "/var/log/myproxy/network-status.txt" ]; then
    cat /var/log/myproxy/network-status.txt
else
    echo "Network auto-configuration not run yet"
    echo "Run: sudo /usr/local/bin/auto-configure-network.sh"
fi

echo ""
echo "=== Current Network Interfaces ==="
ip addr show eth0 | grep 'inet ' | awk '{print "Ethernet: " $2}'
ip addr show wlan0 | grep 'inet ' | awk '{print "WiFi: " $2}' 2>/dev/null || echo "WiFi: not configured"

echo ""
echo "=== Gateway Service Status ==="
if systemctl is-active myproxy-gateway >/dev/null 2>&1; then
    echo "MyProxy Gateway: RUNNING"
else
    echo "MyProxy Gateway: STOPPED"
fi

if systemctl is-active myproxy-network-auto >/dev/null 2>&1; then
    echo "Network Auto-Config: COMPLETED"
else
    echo "Network Auto-Config: NOT RUN"
fi