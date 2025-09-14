#!/bin/bash

# Setup Fixed IPs for Inline Mode
# eth0: 192.168.1.100 (ISP side)
# eth1: 192.168.4.100 (WiFi side)

set -e
LOGFILE="/home/raspberrypi/CODE_STUFF/homeguard/setup-fixed-ips.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOGFILE"
}

log "=== Starting Fixed IP Setup ==="

# Remove any existing bridge configuration
log "Removing bridge configuration..."
sudo nmcli connection show | grep -q "br0" && sudo nmcli connection delete br0 || log "No br0 to delete"

# Configure eth0 with fixed IP for ISP side (192.168.1.100)
log "Configuring eth0 (ISP side): 192.168.1.100/24"
sudo nmcli connection modify "Wired connection 1" \
    ipv4.method manual \
    ipv4.addresses "192.168.1.100/24" \
    ipv4.gateway "192.168.1.1" \
    ipv4.dns "8.8.8.8,8.8.4.4" \
    connection.autoconnect yes

# Configure eth1 with fixed IP for WiFi side (192.168.4.100)
log "Configuring eth1 (WiFi side): 192.168.4.100/24"
sudo nmcli connection modify "Wired connection 2" \
    ipv4.method manual \
    ipv4.addresses "192.168.4.100/24" \
    ipv4.gateway "" \
    ipv4.dns "" \
    connection.autoconnect yes

# Enable IP forwarding for traffic to pass through
log "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-ip-forward.conf
sudo sysctl -p /etc/sysctl.d/99-ip-forward.conf

# Setup basic iptables for forwarding (no NAT needed, just forward)
log "Setting up traffic forwarding rules..."
sudo iptables -t filter -F FORWARD
sudo iptables -t filter -A FORWARD -i eth0 -o eth1 -j ACCEPT
sudo iptables -t filter -A FORWARD -i eth1 -o eth0 -j ACCEPT

# Save iptables rules
sudo sh -c 'iptables-save > /etc/iptables/rules.v4'

# Restart networking
log "Restarting network connections..."
sudo nmcli connection down "Wired connection 1" || true
sudo nmcli connection down "Wired connection 2" || true
sleep 2
sudo nmcli connection up "Wired connection 1"
sudo nmcli connection up "Wired connection 2"

log "=== Fixed IP Setup Complete ==="
log "eth0: 192.168.1.100 (ISP side)"
log "eth1: 192.168.4.100 (WiFi side)"
log "SSH should be accessible from both sides once inline"