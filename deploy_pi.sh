#!/bin/bash

# MyProxy Raspberry Pi Deployment Script
# Configures Raspberry Pi as network gateway with TOTP authentication

set -e  # Exit on any error

echo "🥧 MyProxy Raspberry Pi Deployment Starting..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
apt-get update && apt-get upgrade -y

# Install required packages
echo "📦 Installing required packages..."
apt-get install -y \
    docker.io \
    docker-compose \
    iptables \
    hostapd \
    dnsmasq \
    python3 \
    python3-pip \
    git \
    curl \
    net-tools

# Enable Docker service
echo "🐳 Configuring Docker..."
systemctl enable docker
systemctl start docker
usermod -aG docker pi

# Configure network interfaces
echo "🌐 Configuring network interfaces..."
cat > /etc/dhcpcd.conf.backup <<EOF
# Backup of original dhcpcd.conf created by MyProxy deployment
$(cat /etc/dhcpcd.conf)
EOF

cat >> /etc/dhcpcd.conf <<EOF

# MyProxy Configuration
interface wlan0
static ip_address=192.168.4.1/24
nohook wpa_supplicant
EOF

# Configure hostapd (WiFi Access Point)
echo "📡 Configuring WiFi Access Point..."
cat > /etc/hostapd/hostapd.conf <<EOF
interface=wlan0
driver=nl80211
ssid=MyProxy-Gateway
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=MyProxy123!
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

# Configure dnsmasq (DHCP server)
echo "🌐 Configuring DHCP server..."
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup

cat > /etc/dnsmasq.conf <<EOF
# MyProxy DHCP Configuration
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h

# Route all DNS queries to MyProxy container
server=192.168.4.1
EOF

# Enable IP forwarding
echo "🔄 Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Create MyProxy systemd service
echo "⚙️ Creating MyProxy systemd service..."
cat > /etc/systemd/system/myproxy.service <<EOF
[Unit]
Description=MyProxy Network Gateway
Requires=docker.service
After=docker.service network.target

[Service]
Type=forking
RemainAfterExit=true
WorkingDirectory=/home/pi/myProxy
ExecStart=/usr/bin/docker-compose -f docker-compose.pi.yml up -d
ExecStop=/usr/bin/docker-compose -f docker-compose.pi.yml down
TimeoutStartSec=0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create Pi-specific docker-compose file
echo "🐳 Creating Pi docker-compose configuration..."
mkdir -p /home/pi/myProxy
cat > /home/pi/myProxy/docker-compose.pi.yml <<EOF
version: '3.8'

services:
  myproxy-gateway:
    image: myproxy:latest
    container_name: myproxy-gateway
    restart: unless-stopped
    ports:
      - "80:8080"     # HTTP on port 80
      - "8888:8888"   # HTTP Proxy
    networks:
      - myproxy-network
    volumes:
      - myproxy-data:/app/data
      - ./totp_secrets.json:/app/data/totp_secrets.json
    environment:
      - MYPROXY_DATABASE_URL=sqlite+aiosqlite:////app/data/myproxy.db
      - MYPROXY_DEBUG=false
      - MYPROXY_WEB_HOST=0.0.0.0
      - MYPROXY_WEB_PORT=8080
      - MYPROXY_AUTO_RECOVERY=true
      - MYPROXY_GATEWAY_INTERFACE=wlan0
      - MYPROXY_CLIENT_INTERFACE=eth0
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    privileged: true
    sysctls:
      - net.ipv4.ip_forward=1

networks:
  myproxy-network:
    driver: bridge

volumes:
  myproxy-data:
    name: myproxy-data
EOF

# Set ownership
chown -R pi:pi /home/pi/myProxy

# Enable services
echo "🔧 Enabling services..."
systemctl daemon-reload
systemctl enable hostapd
systemctl enable dnsmasq
systemctl enable myproxy

# Configure iptables rules for NAT
echo "🔥 Configuring iptables NAT rules..."
cat > /etc/rc.local <<EOF
#!/bin/bash
# MyProxy iptables configuration

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure NAT for internet access through eth0
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

# Redirect HTTP traffic to MyProxy container
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.4.1:80

exit 0
EOF

chmod +x /etc/rc.local

# Create TOTP secrets file
echo "🔑 Setting up TOTP secrets..."
if [ ! -f /home/pi/myProxy/totp_secrets.json ]; then
    cat > /home/pi/myProxy/totp_secrets.json <<EOF
{
  "15min": "JBSWY3DPEHPK3PXP",
  "30min": "JBSWY3DPEHPK3PXP",
  "1hr": "JBSWY3DPEHPK3PXP",
  "2hr": "JBSWY3DPEHPK3PXP",
  "4hr": "JBSWY3DPEHPK3PXP",
  "24hr": "JBSWY3DPEHPK3PXP",
  "1week": "JBSWY3DPEHPK3PXP",
  "forever": "JBSWY3DPEHPK3PXP"
}
EOF
fi

chown pi:pi /home/pi/myProxy/totp_secrets.json

# Create startup script for easier management
cat > /home/pi/myProxy/start_myproxy.sh <<EOF
#!/bin/bash
cd /home/pi/myProxy
sudo systemctl start myproxy
echo "🚀 MyProxy started!"
echo "📱 Connect to WiFi: MyProxy-Gateway (password: MyProxy123!)"
echo "🌐 Open browser to: http://192.168.4.1"
echo "📊 Check status: docker logs myproxy-gateway"
EOF

chmod +x /home/pi/myProxy/start_myproxy.sh

cat > /home/pi/myProxy/stop_myproxy.sh <<EOF
#!/bin/bash
cd /home/pi/myProxy
sudo systemctl stop myproxy
echo "🛑 MyProxy stopped!"
EOF

chmod +x /home/pi/myProxy/stop_myproxy.sh

# Final setup message
echo ""
echo "🎉 MyProxy Raspberry Pi deployment completed!"
echo ""
echo "📋 Next steps:"
echo "1. Copy your MyProxy Docker image to this Pi"
echo "2. Reboot the Pi: sudo reboot"
echo "3. After reboot, MyProxy will start automatically"
echo ""
echo "📱 Usage:"
echo "• WiFi Network: MyProxy-Gateway"
echo "• WiFi Password: MyProxy123!"
echo "• Web Interface: http://192.168.4.1"
echo ""
echo "🔧 Management:"
echo "• Start: /home/pi/myProxy/start_myproxy.sh"
echo "• Stop: /home/pi/myProxy/stop_myproxy.sh"
echo "• Logs: docker logs myproxy-gateway"
echo "• Status: systemctl status myproxy"
echo ""
echo "⚠️  REMEMBER TO REBOOT: sudo reboot"
echo ""