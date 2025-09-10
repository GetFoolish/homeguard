#!/bin/bash

# MyProxy Bridge Configuration Script  
# Configures Raspberry Pi as transparent network bridge/gateway

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration variables (will be auto-detected)
WAN_INTERFACE=""    # Connected to ISP router (auto-detect)
LAN_INTERFACE=""    # Connected to WiFi router (auto-detect)
BRIDGE_IP="192.168.4.71"  # Pi's management IP
CURRENT_IP="192.168.4.71"  # Current IP from CLAUDE.md

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

# Function to detect network interfaces for bridge mode
detect_bridge_interfaces() {
    log "🔍 Detecting network interfaces for bridge mode..."
    
    # Get all network interfaces (excluding loopback)
    ALL_INTERFACES=$(ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | awk -F': ' '{print $2}' | cut -d'@' -f1)
    
    # Separate ethernet and wifi interfaces
    ETH_INTERFACES=$(echo "$ALL_INTERFACES" | grep -E '^(eth|en)' || true)
    WIFI_INTERFACES=$(echo "$ALL_INTERFACES" | grep -E '^(wlan|wl)' || true)
    USB_ETH_INTERFACES=$(lsusb | grep -i ethernet || true)
    
    log "📊 Available interfaces:"
    echo "$ALL_INTERFACES" | while read -r iface; do
        if [ -n "$iface" ]; then
            STATUS=$(ip link show "$iface" | grep -q 'state UP' && echo "🟢 UP" || echo "🔴 DOWN")
            TYPE=$(echo "$iface" | grep -E '^(eth|en)' > /dev/null && echo "Ethernet" || \
                   echo "$iface" | grep -E '^(wlan|wl)' > /dev/null && echo "WiFi" || echo "Other")
            echo "   $iface: $TYPE $STATUS"
        fi
    done
    
    # Auto-detect WAN interface (currently connected to internet)
    CURRENT_DEFAULT_ROUTE=$(ip route | grep default | head -n1 | awk '{print $5}' || echo "")
    
    if [ -n "$CURRENT_DEFAULT_ROUTE" ]; then
        WAN_INTERFACE="$CURRENT_DEFAULT_ROUTE"
        log_success "WAN interface detected: $WAN_INTERFACE (current default route)"
    else
        # Fallback to first ethernet interface
        WAN_INTERFACE=$(echo "$ETH_INTERFACES" | head -n1)
        log_warning "Using first ethernet interface as WAN: $WAN_INTERFACE"
    fi
    
    # Auto-detect LAN interface
    if [ -n "$USB_ETH_INTERFACES" ]; then
        # Prefer USB ethernet adapter for LAN
        LAN_INTERFACE=$(echo "$ALL_INTERFACES" | grep -E '^(eth1|enx|usb)' | head -n1 || echo "")
        if [ -z "$LAN_INTERFACE" ]; then
            LAN_INTERFACE=$(echo "$ETH_INTERFACES" | grep -v "$WAN_INTERFACE" | head -n1)
        fi
        log_success "LAN interface detected: $LAN_INTERFACE (USB Ethernet adapter)"
    elif [ -n "$WIFI_INTERFACES" ]; then
        # Use WiFi as LAN interface
        LAN_INTERFACE=$(echo "$WIFI_INTERFACES" | head -n1)
        log_success "LAN interface detected: $LAN_INTERFACE (WiFi interface)"
    else
        log_error "Cannot detect LAN interface!"
        log_error "Bridge mode requires at least 2 network interfaces"
        return 1
    fi
    
    # Validate interface selection
    if [ "$WAN_INTERFACE" = "$LAN_INTERFACE" ]; then
        log_error "WAN and LAN interfaces cannot be the same!"
        log_error "WAN: $WAN_INTERFACE, LAN: $LAN_INTERFACE"
        return 1
    fi
    
    log_success "🌉 Bridge configuration:"
    log "   WAN (ISP): $WAN_INTERFACE"
    log "   LAN (Local): $LAN_INTERFACE"
    log "   Management IP: $BRIDGE_IP"
    
    export WAN_INTERFACE LAN_INTERFACE
}

# Function to backup existing network configuration
backup_network_config() {
    log "💾 Backing up existing network configuration..."
    
    BACKUP_DIR="/etc/myproxy/backups/bridge_$(date +%Y%m%d_%H%M%S)"
    sudo mkdir -p "$BACKUP_DIR"
    
    # Backup important network files
    [ -f /etc/dhcpcd.conf ] && sudo cp /etc/dhcpcd.conf "$BACKUP_DIR/"
    [ -f /etc/netplan/50-cloud-init.yaml ] && sudo cp /etc/netplan/50-cloud-init.yaml "$BACKUP_DIR/"
    sudo ip route save table all > "$BACKUP_DIR/routes.backup" 2>/dev/null || true
    sudo iptables-save > "$BACKUP_DIR/iptables.backup" 2>/dev/null || true
    
    log_success "Network configuration backed up to: $BACKUP_DIR"
}

# Function to install bridge utilities
install_bridge_packages() {
    log "📦 Installing bridge utilities..."
    
    # Update package list
    sudo apt-get update -q
    
    # Install bridge utilities and traffic control tools
    sudo apt-get install -y \
        bridge-utils \
        iptables-persistent \
        ethtool \
        tcpdump \
        net-tools \
        dnsutils
    
    log_success "Bridge utilities installed"
}

# Function to configure bridge interfaces
configure_bridge_interfaces() {
    log "🌉 Configuring bridge interfaces..."
    
    # Create bridge interface configuration
    sudo tee /etc/dhcpcd.conf.bridge > /dev/null <<EOF
# MyProxy Bridge Mode Configuration
# Original dhcpcd.conf backed up

# WAN Interface (ISP connection)
interface $WAN_INTERFACE
# Use DHCP for WAN (or configure static if needed)

# LAN Interface (Local network) 
interface $LAN_INTERFACE
static ip_address=$BRIDGE_IP/24

# Disable IPv6 for now
noipv6
EOF
    
    # Replace current dhcpcd.conf
    sudo cp /etc/dhcpcd.conf.bridge /etc/dhcpcd.conf
    
    log_success "Bridge interfaces configured"
}

# Function to configure transparent proxy with iptables
configure_transparent_proxy() {
    log "🔄 Configuring transparent proxy with iptables..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p > /dev/null
    
    # Clear existing rules
    sudo iptables -F
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    
    # Basic NAT for internet access (fallback)
    sudo iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    
    # Forward traffic between interfaces  
    sudo iptables -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
    
    # Allow management access to Pi itself
    sudo iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 80 -j ACCEPT   # MyProxy web
    sudo iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 22 -j ACCEPT   # SSH
    sudo iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 8080 -j ACCEPT # MyProxy admin
    
    # Create MYPROXY_FILTER chain for transparent filtering
    sudo iptables -t filter -N MYPROXY_FILTER 2>/dev/null || true
    sudo iptables -t filter -F MYPROXY_FILTER
    
    # Insert MyProxy filtering into FORWARD chain
    sudo iptables -I FORWARD 1 -i "$LAN_INTERFACE" -j MYPROXY_FILTER
    
    # Default policy: allow established connections
    sudo iptables -I MYPROXY_FILTER 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Allow local traffic (Pi management)
    sudo iptables -I MYPROXY_FILTER 2 -d "$BRIDGE_IP" -j ACCEPT
    
    # Default action for new connections: let MyProxy container decide
    # (MyProxy will add specific ACCEPT/DROP rules for authenticated devices)
    
    # Save iptables rules
    sudo netfilter-persistent save
    
    log_success "Transparent proxy configured with MYPROXY_FILTER chain"
}

# Function to configure bridge networking  
configure_network_bridge() {
    log "🌐 Setting up network bridge..."
    
    # For true bridge mode, we could create a bridge interface
    # For now, we'll use routing-based approach which is more flexible
    
    # Restart networking to apply interface configuration
    sudo systemctl restart dhcpcd
    
    # Wait for interfaces to come up
    sleep 5
    
    # Verify interfaces are up
    if ip link show "$WAN_INTERFACE" | grep -q 'state UP'; then
        log_success "WAN interface $WAN_INTERFACE: UP"
    else
        log_warning "WAN interface $WAN_INTERFACE: DOWN (may need manual configuration)"
    fi
    
    if ip link show "$LAN_INTERFACE" | grep -q 'state UP'; then
        log_success "LAN interface $LAN_INTERFACE: UP"
    else
        log_warning "LAN interface $LAN_INTERFACE: DOWN (trying to bring up...)"
        sudo ip link set "$LAN_INTERFACE" up
    fi
}

# Function to show bridge status and configuration
show_bridge_info() {
    log "📊 Bridge Mode Configuration Complete!"
    echo ""
    log_success "🌉 MyProxy Bridge Mode is ready!"
    echo ""
    echo "🔗 Network Topology:"
    echo "   ISP Router → Pi ($WAN_INTERFACE) → Pi ($LAN_INTERFACE) → WiFi Router"
    echo ""
    echo "⚙️  Configuration:"
    echo "   WAN Interface: $WAN_INTERFACE"
    echo "   LAN Interface: $LAN_INTERFACE"  
    echo "   Management IP: $BRIDGE_IP"
    echo ""
    echo "🌐 Access MyProxy:"
    echo "   Web Interface: http://$BRIDGE_IP"
    echo "   SSH Access: ssh pi@$BRIDGE_IP"
    echo ""
    echo "📋 Next Steps:"
    echo "   1. Connect $WAN_INTERFACE to ISP router"
    echo "   2. Connect $LAN_INTERFACE to WiFi router's WAN port"
    echo "   3. Start MyProxy service"
    echo "   4. All household traffic will flow through MyProxy!"
    echo ""
    echo "📊 Current Interface Status:"
    ip link show | grep -E '^[0-9]+:' | grep -E "(${WAN_INTERFACE}|${LAN_INTERFACE})" | while read -r line; do
        IFACE=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
        STATUS=$(echo "$line" | grep -q 'state UP' && echo "🟢 UP" || echo "🔴 DOWN")
        echo "   $IFACE: $STATUS"
    done
    echo ""
}

# Main configuration function
main() {
    log "🚀 Configuring MyProxy Bridge Mode..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Run configuration steps
    detect_bridge_interfaces
    backup_network_config
    install_bridge_packages
    configure_bridge_interfaces
    configure_transparent_proxy
    configure_network_bridge
    show_bridge_info
    
    log_success "🎉 Bridge mode configuration completed successfully!"
    log_warning "⚠️  IMPORTANT: Physically connect cables as shown above"
    log_warning "⚠️  IMPORTANT: Restart MyProxy service to apply bridge settings"
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi