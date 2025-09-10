#!/bin/bash

echo "🧹 Cleaning up Pi network configuration..."

# Stop all AP-related services
echo "Stopping AP services..."
sudo systemctl stop hostapd 2>/dev/null || true
sudo systemctl stop dnsmasq 2>/dev/null || true

# Disable AP services from auto-starting
echo "Disabling AP services..."
sudo systemctl disable hostapd 2>/dev/null || true
sudo systemctl disable dnsmasq 2>/dev/null || true

# Delete problematic AP connections
echo "Removing AP connections..."
sudo nmcli connection delete myproxy-ap 2>/dev/null || echo "No myproxy-ap found"
sudo nmcli connection delete "Hotspot" 2>/dev/null || echo "No Hotspot found"

# Remove AP configuration files
echo "Cleaning up config files..."
sudo rm -f /etc/hostapd/hostapd.conf.backup
sudo rm -f /etc/dnsmasq.conf.backup

# Reset dnsmasq to original state
echo "Resetting dnsmasq..."
sudo systemctl stop dnsmasq
if [ -f /etc/dnsmasq.conf.backup ]; then
    sudo mv /etc/dnsmasq.conf.backup /etc/dnsmasq.conf
else
    # Create minimal dnsmasq config
    sudo tee /etc/dnsmasq.conf > /dev/null <<EOF
# Minimal dnsmasq configuration
domain-needed
bogus-priv
EOF
fi

# Clear any custom iptables rules
echo "Clearing iptables rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true

# Restart NetworkManager to clean state
echo "Restarting NetworkManager..."
sudo systemctl restart NetworkManager

# Wait for network to stabilize
echo "Waiting for network to stabilize..."
sleep 5

# Test internet connectivity
echo "Testing internet connectivity..."
if ping -c 3 google.com > /dev/null 2>&1; then
    echo "✅ Internet connectivity restored"
    echo "📍 Current IP addresses:"
    ip addr show | grep "inet " | grep -v "127.0.0.1"
else
    echo "❌ No internet connectivity - may need manual WiFi reconnection"
    echo "📋 Available WiFi networks:"
    sudo nmcli device wifi list | head -10
fi

echo ""
echo "🎉 Network cleanup complete!"
echo "💡 If internet still doesn't work, manually reconnect to WiFi:"
echo "    sudo nmcli device wifi connect 'ArkaNet' password 'YourPassword'"