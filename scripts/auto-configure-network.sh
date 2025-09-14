#!/bin/bash
# MyProxy Auto Network Configuration
# Automatically detects network environment and configures interfaces

set -e

# Check for test mode
TEST_MODE=false
if [ "$1" = "--test" ] || [ "$1" = "-t" ]; then
    TEST_MODE=true
    echo "=== TEST MODE: Detection only, no changes will be made ==="
    echo ""
fi

# Logging
LOG_FILE="/var/log/myproxy/auto-network.log"
mkdir -p "$(dirname "$LOG_FILE")"

# Clear previous logs and start fresh
> "$LOG_FILE"

log() {
    local prefix=""
    if [ "$TEST_MODE" = true ]; then
        prefix="[TEST] "
    fi
    echo "${prefix}[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    local prefix=""
    if [ "$TEST_MODE" = true ]; then
        prefix="[TEST] "
    fi
    echo "${prefix}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE" >&2
}

# Network detection functions
detect_gateway() {
    local interface="$1"
    # Try to get default gateway for interface
    ip route show dev "$interface" 2>/dev/null | grep default | awk '{print $3}' | head -n1
}

ping_gateway() {
    local gateway="$1"
    # Quick ping test (1 second timeout)
    ping -c 1 -W 1 "$gateway" >/dev/null 2>&1
}

get_network_info() {
    local gateway="$1"
    # Extract network base (e.g., 192.168.1.1 -> 192.168.1)
    echo "$gateway" | cut -d. -f1-3
}

configure_static_ip() {
    local interface="$1"
    local ip_address="$2"
    local gateway="$3"
    local connection_name="$4"
    
    log "Configuring $interface with static IP: $ip_address, gateway: $gateway"
    
    # Configure using NetworkManager
    nmcli connection modify "$connection_name" \
        ipv4.method manual \
        ipv4.addresses "$ip_address/24" \
        ipv4.gateway "$gateway" \
        ipv4.dns "8.8.8.8,8.8.4.4" \
        connection.autoconnect yes
    
    # Bring connection up
    nmcli connection up "$connection_name" || true
    
    # Wait a moment for configuration to apply
    sleep 3
}

# Main detection logic
log "=== MyProxy Auto Network Configuration Starting ==="

# Get available network interfaces
ETHERNET_INTERFACE="eth0"
WIFI_INTERFACE="wlan0"

# Check if interfaces exist
if ! ip link show "$ETHERNET_INTERFACE" >/dev/null 2>&1; then
    log_error "Ethernet interface $ETHERNET_INTERFACE not found"
    exit 1
fi

# Detect current network environment
log "Detecting network environment..."

# First, try to get current gateway from ethernet
CURRENT_GATEWAY=$(detect_gateway "$ETHERNET_INTERFACE")
if [ -z "$CURRENT_GATEWAY" ]; then
    if [ "$TEST_MODE" = true ]; then
        log "No gateway detected on ethernet interface"
        log "In production mode, would attempt DHCP discovery"
    else
        # Try DHCP first to detect network
        log "No gateway detected, attempting DHCP discovery..."
        nmcli connection modify "Wired connection 1" ipv4.method auto
        nmcli connection up "Wired connection 1" || true
        sleep 5
        CURRENT_GATEWAY=$(detect_gateway "$ETHERNET_INTERFACE")
    fi
fi

# Test common gateway addresses if still no detection
COMMON_GATEWAYS="192.168.1.1 192.168.4.1 192.168.0.1 10.0.0.1 172.16.0.1"

DETECTED_GATEWAY=""
DETECTED_NETWORK=""

if [ -n "$CURRENT_GATEWAY" ] && ping_gateway "$CURRENT_GATEWAY"; then
    DETECTED_GATEWAY="$CURRENT_GATEWAY"
    DETECTED_NETWORK=$(get_network_info "$CURRENT_GATEWAY")
    log "Detected active gateway: $DETECTED_GATEWAY (network: $DETECTED_NETWORK.x)"
else
    log "Testing common gateway addresses..."
    for gw in $COMMON_GATEWAYS; do
        log "Testing gateway: $gw"
        if ping_gateway "$gw"; then
            DETECTED_GATEWAY="$gw"
            DETECTED_NETWORK=$(get_network_info "$gw")
            log "Found working gateway: $DETECTED_GATEWAY (network: $DETECTED_NETWORK.x)"
            break
        fi
    done
fi

if [ -z "$DETECTED_GATEWAY" ]; then
    log_error "No working gateway detected! Cannot configure network."
    log_error "Manual configuration required."
    exit 1
fi

# Determine configuration based on detected network
PI_ETHERNET_IP=""
PI_WIFI_IP="192.168.4.100"  # WiFi always stays on .4.100 for backup access
NETWORK_MODE=""

case "$DETECTED_NETWORK" in
    "192.168.1")
        PI_ETHERNET_IP="192.168.1.100"
        NETWORK_MODE="inline_production"
        log "Detected: Production inline environment (ISP router at 192.168.1.1)"
        ;;
    "192.168.4")
        PI_ETHERNET_IP="192.168.4.200"
        NETWORK_MODE="current_test"
        log "Detected: Current test environment (router at 192.168.4.1)"
        ;;
    "192.168.0")
        PI_ETHERNET_IP="192.168.0.100"
        NETWORK_MODE="standard_home"
        log "Detected: Standard home network (router at 192.168.0.1)"
        ;;
    "10.0.0")
        PI_ETHERNET_IP="10.0.0.100"
        NETWORK_MODE="enterprise"
        log "Detected: Enterprise/business network (router at 10.0.0.1)"
        ;;
    *)
        PI_ETHERNET_IP="$DETECTED_NETWORK.100"
        NETWORK_MODE="custom"
        log "Detected: Custom network ($DETECTED_GATEWAY)"
        ;;
esac

log "Network configuration plan:"
log "  Mode: $NETWORK_MODE"
log "  Ethernet ($ETHERNET_INTERFACE): $PI_ETHERNET_IP"
log "  WiFi ($WIFI_INTERFACE): $PI_WIFI_IP (backup access)"
log "  Gateway: $DETECTED_GATEWAY"

if [ "$TEST_MODE" = true ]; then
    log ""
    log "=== TEST MODE SUMMARY ==="
    log ""
    log "Current Network State:"
    CURRENT_ETH_IP=$(ip addr show "$ETHERNET_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo 'none')
    CURRENT_WIFI_IP=$(ip addr show "$WIFI_INTERFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo 'none')
    CURRENT_DEFAULT_GW=$(ip route show default | awk '{print $3}' | head -n1 || echo 'none')
    
    log "  Current ethernet IP: $CURRENT_ETH_IP"
    log "  Current WiFi IP: $CURRENT_WIFI_IP"
    log "  Current default gateway: $CURRENT_DEFAULT_GW"
    log ""
    log "Detection Results:"
    log "  Detected gateway: $DETECTED_GATEWAY"
    log "  Detected network: $DETECTED_NETWORK.x"
    log "  Environment type: $NETWORK_MODE"
    log ""
    log "Proposed Configuration:"
    log "  Would configure ethernet to: $PI_ETHERNET_IP"
    log "  Would set gateway to: $DETECTED_GATEWAY"
    log "  WiFi backup would be: $PI_WIFI_IP"
    log ""
    log "Access points after configuration would be:"
    log "  SSH Primary: ssh raspberrypi@$PI_ETHERNET_IP"
    log "  SSH Backup: ssh raspberrypi@192.168.4.100 (if WiFi available)"
    log "  VNC Primary: $PI_ETHERNET_IP:5900"
    log "  Web Admin: http://$PI_ETHERNET_IP:8080/admin"
    log ""
    log "Network Changes Required:"
    if [ "$CURRENT_ETH_IP" = "$PI_ETHERNET_IP" ]; then
        log "  ✓ Ethernet IP: No change needed (already $PI_ETHERNET_IP)"
    else
        log "  → Ethernet IP: $CURRENT_ETH_IP → $PI_ETHERNET_IP"
    fi
    
    if [ "$CURRENT_DEFAULT_GW" = "$DETECTED_GATEWAY" ]; then
        log "  ✓ Gateway: No change needed (already $DETECTED_GATEWAY)"
    else
        log "  → Gateway: $CURRENT_DEFAULT_GW → $DETECTED_GATEWAY"
    fi
    log ""
    log "=== TEST MODE: No changes made ==="
    log "Run without --test flag to apply configuration"
    exit 0
fi

# Configure ethernet interface
configure_static_ip "$ETHERNET_INTERFACE" "$PI_ETHERNET_IP" "$DETECTED_GATEWAY" "Wired connection 1"

# Ensure WiFi backup access is configured (if WiFi available)
if ip link show "$WIFI_INTERFACE" >/dev/null 2>&1; then
    # Only configure WiFi backup if we're not on the .4.x network
    if [ "$DETECTED_NETWORK" != "192.168.4" ]; then
        log "Configuring WiFi backup access..."
        
        # Check if WiFi connection exists
        WIFI_CONNECTION=$(nmcli connection show | grep "$WIFI_INTERFACE" | head -n1 | awk '{print $1}')
        if [ -n "$WIFI_CONNECTION" ]; then
            # Configure WiFi with backup IP (assuming it connects to .4.1 network)
            nmcli connection modify "$WIFI_CONNECTION" \
                ipv4.method manual \
                ipv4.addresses "192.168.4.100/22" \
                ipv4.gateway "192.168.4.1" \
                ipv4.dns "8.8.8.8,8.8.4.4" \
                connection.autoconnect yes || true
        fi
    fi
fi

# Wait for network to stabilize
sleep 5

# Verify configuration
log "Verifying network configuration..."

# Test ethernet connectivity
if ping_gateway "$DETECTED_GATEWAY"; then
    log "✓ Ethernet connectivity verified: $PI_ETHERNET_IP -> $DETECTED_GATEWAY"
    
    # Get actual assigned IP to confirm
    ACTUAL_IP=$(ip addr show "$ETHERNET_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    log "✓ Ethernet IP confirmed: $ACTUAL_IP"
else
    log_error "✗ Ethernet connectivity failed!"
fi

# Test WiFi if configured
if [ "$DETECTED_NETWORK" != "192.168.4" ] && ip addr show "$WIFI_INTERFACE" | grep -q 'inet '; then
    WIFI_IP=$(ip addr show "$WIFI_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    log "✓ WiFi backup configured: $WIFI_IP"
fi

# Update MyProxy gateway configuration
GATEWAY_CONFIG_FILE="/etc/myproxy/gateway.conf"
if [ ! -f "$GATEWAY_CONFIG_FILE" ]; then
    mkdir -p "$(dirname "$GATEWAY_CONFIG_FILE")"
    cat > "$GATEWAY_CONFIG_FILE" << EOF
[GATEWAY]
MODE=transparent
BRIDGE_INTERFACE=br0
WAN_INTERFACE=eth0
LAN_INTERFACE=usb-eth0
ADMIN_PORT=8080
SSH_PORT=22
VNC_PORT=5900
EMERGENCY_FILE=/etc/myproxy/EMERGENCY_TRANSPARENT
EOF
fi

# Update configuration with detected network info
python3 << EOF
import configparser
config = configparser.ConfigParser()
config.read('$GATEWAY_CONFIG_FILE')

if 'NETWORK' not in config:
    config.add_section('NETWORK')

config.set('NETWORK', 'DETECTED_GATEWAY', '$DETECTED_GATEWAY')
config.set('NETWORK', 'DETECTED_NETWORK', '$DETECTED_NETWORK')
config.set('NETWORK', 'NETWORK_MODE', '$NETWORK_MODE')
config.set('NETWORK', 'PI_ETHERNET_IP', '$PI_ETHERNET_IP')
config.set('NETWORK', 'PI_WIFI_IP', '$PI_WIFI_IP')
config.set('NETWORK', 'LAST_DETECTION', '$(date)')

with open('$GATEWAY_CONFIG_FILE', 'w') as f:
    config.write(f)
EOF

log "Updated gateway configuration with network detection results"

# Create network status file for easy checking
cat > /var/log/myproxy/network-status.txt << EOF
MyProxy Network Auto-Configuration Status
=========================================
Detection Time: $(date)
Network Mode: $NETWORK_MODE
Detected Gateway: $DETECTED_GATEWAY
Detected Network: $DETECTED_NETWORK.x

IP Configuration:
- Ethernet ($ETHERNET_INTERFACE): $PI_ETHERNET_IP
- WiFi ($WIFI_INTERFACE): $PI_WIFI_IP

Access Points:
- SSH Primary: ssh raspberrypi@$PI_ETHERNET_IP
- SSH Backup: ssh raspberrypi@192.168.4.100 (if available)
- VNC Primary: $PI_ETHERNET_IP:5900
- VNC Backup: 192.168.4.100:5900 (if available)
- Web Admin Primary: http://$PI_ETHERNET_IP:8080/admin
- Web Admin Backup: http://192.168.4.100:8080/admin (if available)

Gateway Control:
- sudo myproxy-ctl status
- sudo myproxy-ctl set-mode transparent
- sudo myproxy-ctl set-mode totp_enabled
- sudo myproxy-ctl emergency-transparent

Log File: $LOG_FILE
EOF

log "=== Network Auto-Configuration Complete ==="
log "Access the Pi at: $PI_ETHERNET_IP"
log "Backup access (if available): 192.168.4.100"
log "Status file: /var/log/myproxy/network-status.txt"

# Restart MyProxy gateway service if it's enabled
if systemctl is-enabled myproxy-gateway >/dev/null 2>&1; then
    log "Restarting MyProxy gateway service with new network configuration..."
    systemctl restart myproxy-gateway || true
fi

exit 0