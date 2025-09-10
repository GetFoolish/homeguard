#!/bin/bash

echo "🔧 Fixing Pi network configuration..."

# Test internet connectivity
echo "Testing internet..."
if ping -c 3 google.com; then
    echo "✅ Internet is working"
else
    echo "❌ No internet connectivity"
    exit 1
fi

# Delete the problematic myproxy-ap connection
echo "Deleting old AP connection..."
sudo nmcli connection delete myproxy-ap 2>/dev/null || echo "AP connection not found"

# Create new Access Point on 192.168.5.x to avoid conflict with router
echo "Creating new Access Point on 192.168.5.x..."
sudo nmcli connection add type wifi ifname wlan0 con-name myproxy-ap autoconnect no mode ap ssid MyProxy-Gateway
sudo nmcli connection modify myproxy-ap 802-11-wireless-security.key-mgmt wpa-psk
sudo nmcli connection modify myproxy-ap 802-11-wireless-security.psk "MyProxy123!"
sudo nmcli connection modify myproxy-ap ipv4.addresses 192.168.5.1/24
sudo nmcli connection modify myproxy-ap ipv4.method shared

# Update dnsmasq config for new IP range
echo "Updating dnsmasq configuration..."
sudo sed -i 's/192.168.4/192.168.5/g' /etc/dnsmasq.conf

# Restart dnsmasq
sudo systemctl restart dnsmasq

# Activate the new Access Point
echo "Activating Access Point..."
sudo nmcli connection up myproxy-ap

# Check status
echo "Checking AP status..."
sudo systemctl status hostapd --no-pager -l
sudo systemctl status dnsmasq --no-pager -l

echo ""
echo "✅ Setup complete!"
echo "📱 Connect to WiFi: MyProxy-Gateway"
echo "🔑 Password: MyProxy123!"
echo "🌐 AP IP: 192.168.5.1"
echo ""
echo "You can now SSH from your Mac to: ssh raspberrypi@192.168.5.1"