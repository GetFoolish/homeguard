#!/bin/bash

# MyProxy Mode Switching Script
# Allows runtime switching between Access Point and Bridge modes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/myproxy"
MODE_FILE="$CONFIG_DIR/mode.conf"
MYPROXY_DIR="/home/pi/myProxy"

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

# Function to show usage
show_usage() {
    echo "Usage: $0 [bridge|ap|status|auto]"
    echo ""
    echo "Commands:"
    echo "  bridge  - Switch to Bridge Mode (transparent gateway)"
    echo "  ap      - Switch to Access Point Mode (WiFi hotspot)"  
    echo "  status  - Show current mode and system status"
    echo "  auto    - Auto-detect and switch to best mode"
    echo ""
    echo "Examples:"
    echo "  $0 bridge   # Switch to bridge mode"
    echo "  $0 ap       # Switch to access point mode"
    echo "  $0 status   # Show current status"
    echo "  $0 auto     # Auto-detect best mode"
    echo ""
}

# Function to check current mode
get_current_mode() {
    if [ -f "$MODE_FILE" ]; then
        CURRENT_MODE=$(grep '^MODE=' "$MODE_FILE" | cut -d'=' -f2 | tr -d '"' 2>/dev/null || echo "unknown")
    else
        CURRENT_MODE="unknown"
    fi
    echo "$CURRENT_MODE"
}

# Function to show system status
show_status() {
    log "📊 MyProxy System Status"
    echo ""
    
    # Current mode
    CURRENT_MODE=$(get_current_mode)
    if [ "$CURRENT_MODE" = "bridge" ]; then
        log_success "Current Mode: 🌉 Bridge Mode (Transparent Gateway)"
    elif [ "$CURRENT_MODE" = "ap" ]; then
        log_success "Current Mode: 📡 Access Point Mode (WiFi Hotspot)"
    else
        log_warning "Current Mode: ❓ Unknown ($CURRENT_MODE)"
    fi
    
    # Docker service status
    if systemctl is-active --quiet myproxy 2>/dev/null; then
        log_success "MyProxy Service: 🟢 Running"
    else
        log_warning "MyProxy Service: 🔴 Stopped"
    fi
    
    # Docker container status
    if docker ps --format "table {{.Names}}\t{{.Status}}" | grep -q myproxy-gateway; then
        CONTAINER_STATUS=$(docker ps --format "{{.Status}}" --filter "name=myproxy-gateway")
        log_success "MyProxy Container: 🐳 $CONTAINER_STATUS"
    else
        log_warning "MyProxy Container: 🔴 Not running"
    fi
    
    # Network interfaces
    log "🌐 Network Interfaces:"
    ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | while read -r line; do
        IFACE=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
        STATUS=$(echo "$line" | grep -q 'state UP' && echo "🟢 UP" || echo "🔴 DOWN")
        echo "   $IFACE: $STATUS"
    done
    
    # Show configuration file if exists
    if [ -f "$MODE_FILE" ]; then
        echo ""
        log "⚙️  Configuration Details:"
        grep -E '^(MODE|DETECTED_|SELECTION_SOURCE|DETECTION_TIME)=' "$MODE_FILE" 2>/dev/null | while read -r line; do
            echo "   $line"
        done
    fi
    
    echo ""
}

# Function to validate mode before switching
validate_mode_switch() {
    local TARGET_MODE="$1"
    
    log "🔍 Validating mode switch to: $TARGET_MODE"
    
    # Check if we have the necessary interfaces for the target mode
    if [ "$TARGET_MODE" = "bridge" ]; then
        # Bridge mode needs at least 2 network interfaces
        ETH_COUNT=$(ip link show | grep -cE '^[0-9]+: (eth|en)' || echo 0)
        USB_ETH_COUNT=$(lsusb | grep -ci ethernet || echo 0)
        WIFI_COUNT=$(ip link show | grep -cE '^[0-9]+: (wlan|wl)' || echo 0)
        
        TOTAL_INTERFACES=$((ETH_COUNT + USB_ETH_COUNT + WIFI_COUNT))
        
        if [ $TOTAL_INTERFACES -lt 2 ]; then
            log_error "Bridge mode requires at least 2 network interfaces"
            log_error "Current: $ETH_COUNT ethernet + $USB_ETH_COUNT USB ethernet + $WIFI_COUNT WiFi = $TOTAL_INTERFACES total"
            log_error "Consider using Access Point mode instead"
            return 1
        fi
        
        log_success "Bridge mode validation passed: $TOTAL_INTERFACES interfaces available"
        
    elif [ "$TARGET_MODE" = "ap" ]; then
        # Access Point mode needs at least 1 WiFi interface
        WIFI_COUNT=$(ip link show | grep -cE '^[0-9]+: (wlan|wl)' || echo 0)
        
        if [ $WIFI_COUNT -lt 1 ]; then
            log_error "Access Point mode requires at least 1 WiFi interface"
            log_error "Current: $WIFI_COUNT WiFi interfaces found"
            return 1
        fi
        
        log_success "Access Point mode validation passed: $WIFI_COUNT WiFi interface(s) available"
    fi
    
    return 0
}

# Function to switch mode
switch_mode() {
    local TARGET_MODE="$1"
    local CURRENT_MODE=$(get_current_mode)
    
    log "🔄 Switching from $CURRENT_MODE to $TARGET_MODE mode..."
    
    # Validate the switch
    if ! validate_mode_switch "$TARGET_MODE"; then
        log_error "Mode validation failed. Cannot switch to $TARGET_MODE mode."
        return 1
    fi
    
    # If already in target mode, just restart services
    if [ "$CURRENT_MODE" = "$TARGET_MODE" ]; then
        log_warning "Already in $TARGET_MODE mode. Restarting services..."
        systemctl restart myproxy || true
        log_success "Services restarted in $TARGET_MODE mode"
        return 0
    fi
    
    # Stop current services
    log "🛑 Stopping current MyProxy services..."
    systemctl stop myproxy 2>/dev/null || true
    
    # Update configuration file
    log "📝 Updating configuration..."
    sudo mkdir -p "$CONFIG_DIR"
    
    # Create new config with timestamp
    cat > "$MODE_FILE.tmp" <<EOF
# MyProxy Mode Configuration
# Updated on $(date)
# Previous mode: $CURRENT_MODE
# New mode: $TARGET_MODE

MODE="$TARGET_MODE"

# Mode Switch Information
PREVIOUS_MODE="$CURRENT_MODE"
SWITCH_TIME="$(date)"
SWITCH_METHOD="manual"
EOF
    
    sudo mv "$MODE_FILE.tmp" "$MODE_FILE"
    sudo chmod 644 "$MODE_FILE"
    
    # Configure network for new mode
    log "🌐 Configuring network for $TARGET_MODE mode..."
    
    if [ "$TARGET_MODE" = "bridge" ]; then
        # Configure bridge mode networking
        "$SCRIPT_DIR/configure-bridge.sh" || {
            log_error "Bridge configuration failed"
            return 1
        }
    elif [ "$TARGET_MODE" = "ap" ]; then
        # Configure access point mode networking
        "$SCRIPT_DIR/configure-ap.sh" || {
            log_error "Access Point configuration failed"  
            return 1
        }
    fi
    
    # Start services in new mode
    log "🚀 Starting MyProxy in $TARGET_MODE mode..."
    systemctl start myproxy || {
        log_error "Failed to start MyProxy service"
        return 1
    }
    
    # Wait for service to be ready
    log "⏳ Waiting for service to start..."
    sleep 5
    
    # Verify the switch worked
    if systemctl is-active --quiet myproxy; then
        log_success "🎉 Successfully switched to $TARGET_MODE mode!"
        log_success "MyProxy is running in $TARGET_MODE mode"
        
        # Show quick status
        show_status
    else
        log_error "Mode switch failed - service is not running"
        return 1
    fi
}

# Function to auto-detect and switch to best mode
auto_switch() {
    log "🤖 Auto-detecting best mode..."
    
    # Run mode detection
    if ! DETECTED_MODE=$("$SCRIPT_DIR/detect-mode.sh"); then
        log_error "Mode detection failed"
        return 1
    fi
    
    log_success "Auto-detected mode: $DETECTED_MODE"
    
    # Switch to detected mode
    switch_mode "$DETECTED_MODE"
}

# Main function
main() {
    local COMMAND="$1"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    case "$COMMAND" in
        "bridge")
            switch_mode "bridge"
            ;;
        "ap")
            switch_mode "ap"
            ;;
        "status")
            show_status
            ;;
        "auto")
            auto_switch
            ;;
        "help"|"--help"|"-h"|"")
            show_usage
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi