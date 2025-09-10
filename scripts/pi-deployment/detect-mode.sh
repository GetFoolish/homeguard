#!/bin/bash

# MyProxy Mode Detection Script
# Automatically detects the best operational mode based on hardware and configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/myproxy"
MODE_FILE="$CONFIG_DIR/mode.conf"

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

# Function to detect network interfaces
detect_interfaces() {
    log "🔍 Detecting network interfaces..."
    
    # Get all network interfaces (excluding loopback)
    INTERFACES=$(ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | awk -F': ' '{print $2}' | cut -d'@' -f1)
    
    # Count ethernet interfaces
    ETH_INTERFACES=$(echo "$INTERFACES" | grep -E '^eth|^en' || true)
    ETH_COUNT=$(echo "$ETH_INTERFACES" | grep -c . || echo 0)
    
    # Count wireless interfaces  
    WIFI_INTERFACES=$(echo "$INTERFACES" | grep -E '^wlan|^wl' || true)
    WIFI_COUNT=$(echo "$WIFI_INTERFACES" | grep -c . || echo 0)
    
    # Count USB ethernet interfaces
    USB_ETH_INTERFACES=$(lsusb | grep -i ethernet || true)
    USB_ETH_COUNT=$(echo "$USB_ETH_INTERFACES" | grep -c . || echo 0)
    
    log "📊 Interface Detection Results:"
    log "   Ethernet interfaces: $ETH_COUNT ($ETH_INTERFACES)"
    log "   WiFi interfaces: $WIFI_COUNT ($WIFI_INTERFACES)"
    log "   USB Ethernet adapters: $USB_ETH_COUNT"
    
    # Store results for mode decision
    export DETECTED_ETH_COUNT=$ETH_COUNT
    export DETECTED_WIFI_COUNT=$WIFI_COUNT
    export DETECTED_USB_ETH_COUNT=$USB_ETH_COUNT
    export DETECTED_ETH_INTERFACES="$ETH_INTERFACES"
    export DETECTED_WIFI_INTERFACES="$WIFI_INTERFACES"
}

# Function to check for boot parameters
check_boot_params() {
    log "🥾 Checking boot parameters..."
    
    if [ -f /proc/cmdline ]; then
        CMDLINE=$(cat /proc/cmdline)
        
        if echo "$CMDLINE" | grep -q "myproxy.mode=bridge"; then
            log_success "Boot parameter found: myproxy.mode=bridge"
            export BOOT_MODE="bridge"
            return 0
        elif echo "$CMDLINE" | grep -q "myproxy.mode=ap"; then
            log_success "Boot parameter found: myproxy.mode=ap"  
            export BOOT_MODE="ap"
            return 0
        fi
    fi
    
    log "No boot mode parameter found"
    export BOOT_MODE=""
}

# Function to read configuration file
read_config() {
    log "📄 Reading configuration file..."
    
    if [ -f "$MODE_FILE" ]; then
        # Read the mode from config file
        CONFIG_MODE=$(grep '^MODE=' "$MODE_FILE" | cut -d'=' -f2 | tr -d '"' || echo "")
        
        if [ -n "$CONFIG_MODE" ]; then
            log_success "Configuration file mode: $CONFIG_MODE"
            export CONFIG_MODE
            return 0
        fi
    fi
    
    log "No configuration file or mode found"
    export CONFIG_MODE=""
}

# Function to auto-detect best mode based on hardware
auto_detect_mode() {
    log "🤖 Auto-detecting best mode based on hardware..."
    
    # Bridge mode requirements:
    # - At least 2 ethernet interfaces (1 built-in + 1 USB) OR 1 eth + 1 wifi
    # - Suitable for production deployment
    
    TOTAL_NETWORK_INTERFACES=$((DETECTED_ETH_COUNT + DETECTED_USB_ETH_COUNT))
    
    if [ $TOTAL_NETWORK_INTERFACES -ge 2 ]; then
        log_success "Bridge mode detected: $TOTAL_NETWORK_INTERFACES network interfaces available"
        log "   Bridge topology: ISP Router → Pi → WiFi Router"
        export AUTO_MODE="bridge"
        return 0
    elif [ $DETECTED_ETH_COUNT -ge 1 ] && [ $DETECTED_WIFI_COUNT -ge 1 ]; then
        log_success "Hybrid bridge mode possible: $DETECTED_ETH_COUNT ethernet + $DETECTED_WIFI_COUNT WiFi"
        log "   Could use WiFi as WAN or LAN interface"
        export AUTO_MODE="bridge"
        return 0
    elif [ $DETECTED_WIFI_COUNT -ge 1 ]; then
        log_success "Access Point mode detected: WiFi interface available"
        log "   AP topology: Existing Network → Pi (WiFi AP) → Client Devices"
        export AUTO_MODE="ap"
        return 0
    else
        log_warning "Insufficient interfaces for either mode"
        log_error "Need at least 1 WiFi interface for AP mode or 2+ network interfaces for bridge mode"
        export AUTO_MODE="none"
        return 1
    fi
}

# Function to determine final mode
determine_mode() {
    log "🎯 Determining operational mode..."
    
    # Priority order:
    # 1. Boot parameter (highest priority)
    # 2. Configuration file
    # 3. Auto-detection (lowest priority)
    
    FINAL_MODE=""
    
    if [ -n "$BOOT_MODE" ]; then
        FINAL_MODE="$BOOT_MODE"
        log_success "Using boot parameter mode: $FINAL_MODE"
    elif [ -n "$CONFIG_MODE" ]; then
        FINAL_MODE="$CONFIG_MODE"
        log_success "Using configuration file mode: $FINAL_MODE"
    elif [ -n "$AUTO_MODE" ] && [ "$AUTO_MODE" != "none" ]; then
        FINAL_MODE="$AUTO_MODE"
        log_success "Using auto-detected mode: $FINAL_MODE"
    else
        log_error "Cannot determine operational mode!"
        log_error "Please manually configure mode in $MODE_FILE"
        exit 1
    fi
    
    # Validate mode
    if [ "$FINAL_MODE" != "bridge" ] && [ "$FINAL_MODE" != "ap" ]; then
        log_error "Invalid mode: $FINAL_MODE (must be 'bridge' or 'ap')"
        exit 1
    fi
    
    export MYPROXY_MODE="$FINAL_MODE"
    log_success "🎉 Final operational mode: $MYPROXY_MODE"
}

# Function to save detected mode to config
save_mode_config() {
    log "💾 Saving mode configuration..."
    
    # Create config directory
    sudo mkdir -p "$CONFIG_DIR"
    
    # Create config file
    cat > "$MODE_FILE.tmp" <<EOF
# MyProxy Mode Configuration
# Generated on $(date)
# Options: bridge, ap

MODE="$MYPROXY_MODE"

# Hardware Detection Results
DETECTED_ETH_COUNT=$DETECTED_ETH_COUNT
DETECTED_WIFI_COUNT=$DETECTED_WIFI_COUNT
DETECTED_USB_ETH_COUNT=$DETECTED_USB_ETH_COUNT
DETECTED_ETH_INTERFACES="$DETECTED_ETH_INTERFACES"
DETECTED_WIFI_INTERFACES="$DETECTED_WIFI_INTERFACES"

# Mode Selection Source
BOOT_MODE="$BOOT_MODE"
CONFIG_MODE="$CONFIG_MODE"  
AUTO_MODE="$AUTO_MODE"
SELECTION_SOURCE="$([ -n "$BOOT_MODE" ] && echo "boot" || [ -n "$CONFIG_MODE" ] && echo "config" || echo "auto")"

# Timestamp
DETECTION_TIME="$(date)"
EOF
    
    sudo mv "$MODE_FILE.tmp" "$MODE_FILE"
    sudo chmod 644 "$MODE_FILE"
    
    log_success "Mode configuration saved to $MODE_FILE"
}

# Main detection function
main() {
    log "🚀 MyProxy Mode Detection Starting..."
    
    # Check if running as root for network interface access
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root for network interface detection"
        exit 1
    fi
    
    # Run detection steps
    detect_interfaces
    check_boot_params
    read_config
    auto_detect_mode || true  # Don't exit on auto-detect failure
    determine_mode
    save_mode_config
    
    # Output final result for consumption by other scripts
    echo "$MYPROXY_MODE"
    
    log_success "🎉 Mode detection completed: $MYPROXY_MODE"
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi