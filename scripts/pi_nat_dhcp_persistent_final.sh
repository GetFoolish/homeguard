#!/bin/bash
set -e

echo "[1/8] Cleaning up old bridges..."
sudo nmcli con down br0 || true
sudo nmcli con delete br0 || true
sudo ip link delete br0 type bridge || true

echo "[2/8] Configuring WAN (eth0) to use DHCP..."
sudo nmcli con modify eth0 ipv4.method auto
sudo nmcli con up eth0

echo "[3/8] Configuring LAN (eth1) with static IP 192.168.2.1/24..."
sudo nmcli con add type ethernet ifname eth1 con-name eth1-static ipv4.addresses 192.168.2.1/24 ipv4.method manual autoconnect yes || true
sudo nmcli con up eth1-static

echo "[4/8] Enabling IP forwarding permanently..."
sudo sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

echo "[5/8] Setting up NAT (eth1 -> eth0)..."
sudo iptables -t nat -F
sudo iptables -F
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo netfilter-persistent save
sudo netfilter-persistent reload

echo "[6/8] Installing and configuring dnsmasq for LAN DHCP..."
sudo apt install -y dnsmasq
sudo tee /etc/dnsmasq.conf > /dev/null <<EOF
interface=eth1
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=1.1.1.1
server=8.8.8.8
dhcp-range=192.168.2.10,192.168.2.200,24h
dhcp-option=3,192.168.2.1
dhcp-option=6,192.168.2.1
EOF

echo "[7/8] Restarting and enabling dnsmasq..."
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq

echo "[8/8] Setup complete! Pi is now a persistent NAT router with DHCP for LAN."
