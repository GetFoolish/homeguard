#!/bin/bash

# USB Ethernet Detection Script for MyProxy Bridge Mode
# Detects USB ethernet adapter and configures environment variables

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

log "🔍 Detecting USB ethernet adapter for bridge mode..."

# Function to detect USB ethernet interfaces
detect_usb_ethernet() {
    local usb_interfaces=()
    
    # Check for common USB ethernet interface patterns
    for interface in $(ls /sys/class/net/ 2>/dev/null); do
        if [[ -d "/sys/class/net/$interface" ]]; then
            # Check if interface is not the built-in ethernet (eth0) or wireless
            if [[ "$interface" != "eth0" && "$interface" != "lo" && ! "$interface" =~ ^wl ]]; then
                # Check if it's a physical ethernet interface
                if [[ -f "/sys/class/net/$interface/operstate" ]]; then
                    local driver_path="/sys/class/net/$interface/device/driver"
                    if [[ -L "$driver_path" ]]; then
                        local driver=$(readlink "$driver_path" | basename)
                        info "Found interface $interface (driver: $driver)"
                        
                        # Common USB ethernet drivers
                        case "$driver" in
                            "asix"|"ax88179_178a"|"r8152"|"cdc_ether"|"usbnet")
                                usb_interfaces+=("$interface")
                                ;;
                            *)
                                # Check if interface name suggests USB ethernet
                                if [[ "$interface" =~ ^(enx|usb|eth[1-9]) ]]; then
                                    usb_interfaces+=("$interface")
                                fi
                                ;;
                        esac
                    fi
                fi
            fi
        fi
    done
    
    echo "${usb_interfaces[@]}"
}

# Detect available interfaces
log "Scanning network interfaces..."
usb_interfaces=($(detect_usb_ethernet))

if [[ ${#usb_interfaces[@]} -eq 0 ]]; then
    error "No USB ethernet adapter detected!"
    echo ""
    echo "Available interfaces:"
    ls /sys/class/net/ | while read iface; do
        if [[ "$iface" != "lo" ]]; then
            local state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
            echo "  $iface ($state)"
        fi
    done
    echo ""
    error "Please connect a USB ethernet adapter and try again"
    echo "Compatible adapters: USB 3.0 Gigabit, AX88179, RTL8153, etc."
    exit 1
fi

# Select the USB ethernet interface
if [[ ${#usb_interfaces[@]} -eq 1 ]]; then
    USB_ETHERNET="${usb_interfaces[0]}"
    log "✅ Detected USB ethernet adapter: $USB_ETHERNET"
else
    warn "Multiple USB ethernet adapters detected:"
    for i in "${!usb_interfaces[@]}"; do
        echo "  $((i+1)). ${usb_interfaces[i]}"
    done
    
    # Auto-select the first one for now
    USB_ETHERNET="${usb_interfaces[0]}"
    log "🔄 Auto-selected: $USB_ETHERNET"
    warn "You can manually override by setting LAN_INTERFACE environment variable"
fi

# Verify interface status
INTERFACE_STATE=$(cat "/sys/class/net/$USB_ETHERNET/operstate" 2>/dev/null || echo "unknown")
info "Interface $USB_ETHERNET state: $INTERFACE_STATE"

if [[ "$INTERFACE_STATE" == "down" ]]; then
    warn "USB ethernet interface is down, attempting to bring it up..."
    if [[ $EUID -eq 0 ]]; then
        ip link set "$USB_ETHERNET" up
        sleep 2
        INTERFACE_STATE=$(cat "/sys/class/net/$USB_ETHERNET/operstate" 2>/dev/null || echo "unknown")
        info "Interface $USB_ETHERNET state after up: $INTERFACE_STATE"
    else
        warn "Run as root to automatically configure interface"
    fi
fi

# Create bridge mode configuration
log "📝 Creating bridge mode configuration..."

# Create mode configuration directory
mkdir -p /etc/myproxy

# Write bridge mode configuration
cat > /etc/myproxy/mode.conf << EOF
# MyProxy Bridge Mode Configuration
# Generated on $(date)

MYPROXY_MODE=bridge
WAN_INTERFACE=eth0
LAN_INTERFACE=$USB_ETHERNET
MYPROXY_GATEWAY_IP=auto
EOF

log "✅ Bridge mode configuration created"

# Create environment file for Docker
cat > /etc/myproxy/bridge.env << EOF
# MyProxy Bridge Mode Environment Variables
MYPROXY_MODE=bridge
WAN_INTERFACE=eth0
LAN_INTERFACE=$USB_ETHERNET
MYPROXY_GATEWAY_IP=auto
EOF

log "✅ Docker environment file created: /etc/myproxy/bridge.env"

# Display configuration summary
echo ""
log "📊 Bridge Mode Configuration Summary:"
log "   • Mode: Bridge (inline deployment)"
log "   • WAN Interface: eth0 (built-in ethernet)"
log "   • LAN Interface: $USB_ETHERNET (USB ethernet)"
log "   • Network Flow: ISP Router → eth0 → $USB_ETHERNET → WiFi Router"
echo ""

log "🔗 Next Steps for Inline Deployment:"
log "   1. Connect cables: ISP Router → Pi eth0 → Pi $USB_ETHERNET → WiFi Router WAN"
log "   2. Update docker-compose: Use /etc/myproxy/bridge.env"
log "   3. Enable bridge mode: sudo ./scripts/configure-bridge-mode.sh"
log "   4. Start MyProxy: docker-compose -f docker-compose.pi.yml up -d"
echo ""

# Export variables for immediate use
export MYPROXY_MODE=bridge
export WAN_INTERFACE=eth0
export LAN_INTERFACE=$USB_ETHERNET
export MYPROXY_GATEWAY_IP=auto

log "🌉 USB ethernet detection complete - ready for bridge mode!"