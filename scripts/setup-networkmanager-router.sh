#!/bin/bash
set -e

### CONFIG
LAN_IF="eth1"              # connected to mesh router
WAN_IF="eth0"              # connected to ISP router
LAN_IP="192.168.4.1"       # Pi LAN IP
LAN_NETMASK="24"
DHCP_RANGE_START="192.168.4.10"
DHCP_RANGE_END="192.168.4.200"
DHCP_LEASE="24h"
DNS1="1.1.1.1"
DNS2="8.8.8.8"

echo "[1/7] Removing bridge configuration..."
sudo nmcli connection show | grep -q "br0" && sudo nmcli connection delete br0 || echo "No br0 to delete"

echo "[2/7] Configuring WAN interface (eth0) for DHCP..."
sudo nmcli connection modify "Wired connection 1" \
    ipv4.method auto \
    connection.autoconnect yes

echo "[3/7] Configuring LAN interface (eth1) with static IP..."
sudo nmcli connection modify "Wired connection 2" \
    ipv4.method manual \
    ipv4.addresses "${LAN_IP}/${LAN_NETMASK}" \
    ipv4.gateway "" \
    ipv4.dns "" \
    connection.autoconnect yes

echo "[4/7] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

echo "[5/7] Installing dnsmasq & iptables-persistent..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y dnsmasq iptables-persistent

echo "[6/7] Configuring dnsmasq..."
sudo tee /etc/dnsmasq.conf > /dev/null <<DNSEOF
interface=$LAN_IF
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=$DNS1
server=$DNS2
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE
dhcp-option=3,$LAN_IP
dhcp-option=6,$LAN_IP
DNSEOF
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq

echo "[7/7] Setting up NAT with iptables..."
sudo iptables -t nat -F
sudo iptables -F FORWARD

sudo iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE
sudo iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT
sudo iptables -A FORWARD -i $WAN_IF -o $LAN_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

sudo netfilter-persistent save
sudo netfilter-persistent reload

echo "[8/7] Restarting network connections..."
sudo nmcli connection down "Wired connection 1" || true
sudo nmcli connection down "Wired connection 2" || true
sleep 3
sudo nmcli connection up "Wired connection 1"
sudo nmcli connection up "Wired connection 2"

echo "✅ Router mode setup complete!"
echo "SSH back in at: 192.168.4.1"
echo "WAN interface will get IP from ISP router"
