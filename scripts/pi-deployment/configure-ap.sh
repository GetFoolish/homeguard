#!/bin/bash

# MyProxy Access Point Configuration Script
# Configures Raspberry Pi as WiFi Access Point with captive portal

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration variables
AP_SSID="MyProxy-Gateway"
AP_PASSWORD="MyProxy123!"
AP_IP="192.168.4.1"
AP_SUBNET="192.168.4.0/24"
DHCP_START="192.168.4.10" 
DHCP_END="192.168.4.50"
WIFI_INTERFACE="wlan0"
ETH_INTERFACE="eth0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ✅ $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ⚠️  $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ❌ $1"
}

# Function to detect WiFi interface
detect_wifi_interface() {
    log "🔍 Detecting WiFi interface..."
    
    # Find WiFi interfaces
    WIFI_INTERFACES=$(iw dev | grep Interface | awk '{print $2}' || true)
    
    if [ -z "$WIFI_INTERFACES" ]; then
        log_error "No WiFi interfaces found!"
        log_error "Access Point mode requires a WiFi interface"
        return 1
    fi
    
    # Use the first WiFi interface found
    WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | head -n1)
    log_success "Using WiFi interface: $WIFI_INTERFACE"
    
    # Check if interface supports AP mode
    if iw dev "$WIFI_INTERFACE" info | grep -q "type managed"; then
        log_success "WiFi interface supports managed mode"
    else
        log_warning "WiFi interface mode unknown, proceeding anyway"
    fi
}

# Function to backup existing network configuration
backup_network_config() {
    log "💾 Backing up existing network configuration..."
    
    BACKUP_DIR="/etc/myproxy/backups/$(date +%Y%m%d_%H%M%S)"
    sudo mkdir -p "$BACKUP_DIR"
    
    # Backup important network files
    [ -f /etc/dhcpcd.conf ] && sudo cp /etc/dhcpcd.conf "$BACKUP_DIR/"
    [ -f /etc/dnsmasq.conf ] && sudo cp /etc/dnsmasq.conf "$BACKUP_DIR/"
    [ -f /etc/hostapd/hostapd.conf ] && sudo cp /etc/hostapd/hostapd.conf "$BACKUP_DIR/"
    [ -f /etc/wpa_supplicant/wpa_supplicant.conf ] && sudo cp /etc/wpa_supplicant/wpa_supplicant.conf "$BACKUP_DIR/"
    
    log_success "Network configuration backed up to: $BACKUP_DIR"
}

# Function to install required packages
install_packages() {
    log "📦 Installing required packages for Access Point mode..."
    
    # Update package list
    sudo apt-get update -q
    
    # Install hostapd and dnsmasq
    sudo apt-get install -y hostapd dnsmasq iptables-persistent
    
    # Stop services during configuration
    sudo systemctl stop hostapd dnsmasq || true
    
    log_success "Packages installed successfully"
}

# Function to configure static IP for WiFi interface
configure_static_ip() {
    log "🌐 Configuring static IP for WiFi interface..."
    
    # Create dhcpcd configuration for AP mode
    sudo tee /etc/dhcpcd.conf.ap > /dev/null <<EOF
# MyProxy Access Point Configuration
# Original dhcpcd.conf backed up to /etc/myproxy/backups/

# Static IP configuration for Access Point mode
interface $WIFI_INTERFACE
static ip_address=$AP_IP/24
nohook wpa_supplicant

# Use ethernet for internet connectivity
interface $ETH_INTERFACE
# Use DHCP for ethernet (internet connection)
EOF
    
    # Replace current dhcpcd.conf
    sudo cp /etc/dhcpcd.conf.ap /etc/dhcpcd.conf
    
    log_success "Static IP configured: $AP_IP on $WIFI_INTERFACE"
}

# Function to configure hostapd (WiFi Access Point)
configure_hostapd() {
    log "📡 Configuring WiFi Access Point (hostapd)..."
    
    # Create hostapd configuration
    sudo tee /etc/hostapd/hostapd.conf > /dev/null <<EOF
# MyProxy Access Point Configuration
interface=$WIFI_INTERFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$AP_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

# Additional settings for better compatibility
ieee80211n=1
ieee80211d=1
country_code=US
EOF
    
    # Configure hostapd daemon
    sudo tee /etc/default/hostapd > /dev/null <<EOF
# Defaults for hostapd initscript
DAEMON_CONF="/etc/hostapd/hostapd.conf"
EOF
    
    log_success "hostapd configured: SSID=$AP_SSID"
}

# Function to configure dnsmasq (DHCP server)
configure_dnsmasq() {
    log "🌐 Configuring DHCP server (dnsmasq)..."
    
    # Backup original dnsmasq.conf
    [ -f /etc/dnsmasq.conf ] && sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    
    # Create dnsmasq configuration for AP mode
    sudo tee /etc/dnsmasq.conf > /dev/null <<EOF
# MyProxy Access Point DHCP Configuration

# Interface configuration
interface=$WIFI_INTERFACE
bind-interfaces

# DHCP range
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h

# Router and DNS server (this Pi)
dhcp-option=3,$AP_IP    # Default gateway
dhcp-option=6,$AP_IP    # DNS server

# Domain for captive portal detection
address=/myproxy.local/$AP_IP
address=/captive.apple.com/$AP_IP
address=/connectivitycheck.gstatic.com/$AP_IP
address=/clients3.google.com/$AP_IP
address=/nmcheck.gnome.org/$AP_IP

# Captive portal detection redirections
address=/detectportal.firefox.com/$AP_IP
address=/connectivity-check.ubuntu.com/$AP_IP

# Log DHCP activity
log-dhcp

# Don't forward plain names (without a dot or domain part)
domain-needed
# Never forward addresses in the non-routed address spaces
bogus-priv
EOF
    
    log_success "dnsmasq configured: DHCP range $DHCP_START-$DHCP_END"
}

# Function to configure IP forwarding and iptables
configure_forwarding() {
    log "🔄 Configuring IP forwarding and NAT..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p > /dev/null
    
    # Configure iptables for NAT
    sudo iptables -F
    sudo iptables -t nat -F
    sudo iptables -t nat -A POSTROUTING -o "$ETH_INTERFACE" -j MASQUERADE
    sudo iptables -A FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -j ACCEPT
    
    # Redirect HTTP traffic to MyProxy captive portal  
    sudo iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 80 -j DNAT --to-destination "$AP_IP:80"
    sudo iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 443 -j DNAT --to-destination "$AP_IP:80"
    
    # Save iptables rules
    sudo netfilter-persistent save
    
    log_success "IP forwarding and NAT configured"
}

# Function to enable services
enable_services() {
    log "🔧 Enabling Access Point services..."
    
    # Enable services to start on boot
    sudo systemctl enable hostapd
    sudo systemctl enable dnsmasq
    
    # Restart network configuration
    sudo systemctl restart dhcpcd
    
    # Start AP services
    sudo systemctl start hostapd
    sudo systemctl start dnsmasq
    
    # Wait a moment for services to start
    sleep 3
    
    # Check service status
    if sudo systemctl is-active --quiet hostapd; then
        log_success "hostapd service: Running"
    else
        log_warning "hostapd service: Not running (check logs)"
    fi
    
    if sudo systemctl is-active --quiet dnsmasq; then
        log_success "dnsmasq service: Running"
    else
        log_warning "dnsmasq service: Not running (check logs)"
    fi
}

# Function to show AP status and connection info
show_ap_info() {
    log "📊 Access Point Configuration Complete!"
    echo ""
    log_success "🎉 MyProxy Access Point is ready!"
    echo ""
    echo "📱 Connection Details:"
    echo "   WiFi Network: $AP_SSID"
    echo "   WiFi Password: $AP_PASSWORD"
    echo "   Gateway IP: $AP_IP"
    echo "   DHCP Range: $DHCP_START - $DHCP_END"
    echo ""
    echo "🌐 Access MyProxy:"
    echo "   Web Interface: http://$AP_IP"
    echo "   Captive Portal: http://myproxy.local"
    echo ""
    echo "📋 Next Steps:"
    echo "   1. Connect device to '$AP_SSID' WiFi"
    echo "   2. Open browser (captive portal should appear)"
    echo "   3. Authenticate with TOTP code"
    echo "   4. Enjoy controlled internet access!"
    echo ""
    
    # Show current connections
    echo "👥 Current DHCP Leases:"
    if [ -f /var/lib/dhcp/dhcpd.leases ]; then
        sudo cat /var/lib/dhcp/dhcpd.leases | grep -E "lease|client-hostname|hardware ethernet" | tail -10
    elif [ -f /var/lib/dhcpcd5/dhcpcd.leases ]; then
        sudo cat /var/lib/dhcpcd5/dhcpcd.leases | tail -5
    else
        echo "   No active leases found"
    fi
    echo ""
}

# Main configuration function
main() {
    log "🚀 Configuring MyProxy Access Point Mode..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Run configuration steps
    detect_wifi_interface
    backup_network_config
    install_packages
    configure_static_ip
    configure_hostapd
    configure_dnsmasq
    configure_forwarding
    enable_services
    show_ap_info
    
    log_success "🎉 Access Point configuration completed successfully!"
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi