#!/bin/bash

# HomeguardGuard Mode Configuration Script
# Usage: ./set-mode.sh [transparent|totp_testing|totp_full] [testing_ip]

CONFIG_FILE="/etc/homeguard/config.yaml"
SERVICE_NAME="homeguard"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Function to display current mode
show_current_mode() {
    echo "============================================="
    echo "        HomeguardGuard Current Mode"
    echo "============================================="

    if [[ -f "$CONFIG_FILE" ]]; then
        CURRENT_MODE=$(grep "^mode:" "$CONFIG_FILE" | cut -d'"' -f2 | tr -d ' ')
        echo "Current Mode: $CURRENT_MODE"

        if [[ "$CURRENT_MODE" == "totp_testing" ]]; then
            TESTING_IP=$(grep "testing_ip:" "$CONFIG_FILE" | grep -o '"[^"]*"' | tr -d '"')
            echo "Testing IP: $TESTING_IP"
        fi
    else
        echo "Config file not found: $CONFIG_FILE"
    fi
    echo "============================================="
}

# Function to set mode
set_mode() {
    local mode="$1"
    local testing_ip="$2"

    echo "Setting HomeguardGuard to mode: $mode"

    # Update the mode in config file
    sed -i "s/^mode: .*/mode: \"$mode\"/" "$CONFIG_FILE"

    # Update testing IP if provided and mode is totp_testing
    if [[ "$mode" == "totp_testing" && -n "$testing_ip" ]]; then
        sed -i "/testing_ip:/s/: .*/: \"$testing_ip\"/" "$CONFIG_FILE"
        echo "Testing IP set to: $testing_ip"
    fi

    echo "Configuration updated successfully!"

    # Restart service if it's running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "Restarting HomeguardGuard service..."
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo "✅ Service restarted successfully"
        else
            echo "❌ Service failed to restart"
            systemctl status "$SERVICE_NAME"
        fi
    else
        echo "Service is not running. Start it with: sudo systemctl start $SERVICE_NAME"
    fi
}

# Main logic
case "$1" in
    "transparent")
        set_mode "transparent" "$2"
        ;;
    "totp_testing")
        if [[ -z "$2" ]]; then
            echo "Error: totp_testing mode requires a testing IP address"
            echo "Usage: $0 totp_testing <ip_address>"
            exit 1
        fi
        set_mode "totp_testing" "$2"
        ;;
    "totp_full")
        set_mode "totp_full" "$2"
        ;;
    "status"|"show"|"")
        show_current_mode
        ;;
    *)
        echo "Usage: $0 [transparent|totp_testing|totp_full|status]"
        echo ""
        echo "Modes:"
        echo "  transparent   - Allow all traffic through (no filtering)"
        echo "  totp_testing  - Block only specific IP for testing (requires IP)"
        echo "  totp_full     - Block all devices until TOTP authentication"
        echo "  status        - Show current mode"
        echo ""
        echo "Examples:"
        echo "  $0 status"
        echo "  $0 transparent"
        echo "  $0 totp_testing 192.168.2.52"
        echo "  $0 totp_full"
        exit 1
        ;;
esac