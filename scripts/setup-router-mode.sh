#!/bin/bash
set -e

### CONFIG (tailored for your setup)
LAN_IF="eth1"              # connected to mesh router
WAN_IF="eth0"              # connected to ISP router
LAN_IP="192.168.4.1"       # Pi LAN IP
LAN_NETMASK="/24"
DHCP_RANGE_START="192.168.4.10"
DHCP_RANGE_END="192.168.4.200"
DHCP_LEASE="24h"
DNS1="1.1.1.1"
DNS2="8.8.8.8"

echo "[1/6] Backing up configs..."
sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.bak.$(date +%s) || true
sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s) || true

echo "[2/6] Configuring static IP for $LAN_IF..."
if ! grep -q "$LAN_IF" /etc/dhcpcd.conf; then
cat <<EOF | sudo tee -a /etc/dhcpcd.conf

# Added by Pi Router script
interface $LAN_IF
static ip_address=${LAN_IP}${LAN_NETMASK}
EOF
fi
sudo systemctl restart dhcpcd

echo "[3/6] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

echo "[4/6] Installing dnsmasq & iptables-persistent..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y dnsmasq iptables-persistent

echo "[5/6] Configuring dnsmasq..."
sudo tee /etc/dnsmasq.conf > /dev/null <<EOF
interface=$LAN_IF
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=$DNS1
server=$DNS2
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE
dhcp-option=3,$LAN_IP      # default gateway
dhcp-option=6,$LAN_IP      # DNS server
EOF
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq

echo "[6/6] Setting up NAT with iptables..."
sudo iptables -t nat -F
sudo iptables -F FORWARD

sudo iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE
sudo iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT
sudo iptables -A FORWARD -i $WAN_IF -o $LAN_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

sudo netfilter-persistent save
sudo netfilter-persistent reload

echo "✅ Setup complete! Your Pi should now act as a router."