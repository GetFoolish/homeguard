#!/bin/bash

# MyProxy Service Installation Script
# Run this script on your Pi to install MyProxy as a system service

set -e  # Exit on any error

echo "🚀 MyProxy Service Installation Script"
echo "======================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should NOT be run as root"
   echo "   Run as pi user: ./install-service.sh"
   exit 1
fi

# Get current directory and user
CURRENT_DIR=$(pwd)
CURRENT_USER=$(whoami)
SERVICE_NAME="myproxy"

echo "📁 Current directory: $CURRENT_DIR"
echo "👤 Current user: $CURRENT_USER"

# Check if we're in the right directory
if [ ! -f "src/main.py" ] || [ ! -f "myproxy.service" ]; then
    echo "❌ Error: Please run this script from the MyProxy project root directory"
    echo "   Expected files: src/main.py, myproxy.service"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Error: Virtual environment not found"
    echo "   Please create venv first: python3 -m venv venv"
    exit 1
fi

# Update the service file with current paths
echo "🔧 Configuring service file..."
SERVICE_FILE_TEMP="/tmp/myproxy.service.tmp"
cp myproxy.service "$SERVICE_FILE_TEMP"

# Replace paths in service file
sed -i "s|/home/pi/myproxy|$CURRENT_DIR|g" "$SERVICE_FILE_TEMP"
sed -i "s|User=pi|User=$CURRENT_USER|g" "$SERVICE_FILE_TEMP"
sed -i "s|Group=pi|Group=$CURRENT_USER|g" "$SERVICE_FILE_TEMP"

# Make sure main.py is executable
chmod +x src/main.py

echo "📋 Service configuration:"
echo "   Service name: $SERVICE_NAME"
echo "   Working directory: $CURRENT_DIR"
echo "   User: $CURRENT_USER"
echo "   Python: $CURRENT_DIR/venv/bin/python"
echo "   Main script: $CURRENT_DIR/src/main.py"

# Install the service
echo "🔐 Installing service (requires sudo)..."
sudo cp "$SERVICE_FILE_TEMP" "/etc/systemd/system/$SERVICE_NAME.service"
sudo systemctl daemon-reload

# Enable and start the service
echo "🚀 Enabling and starting service..."
sudo systemctl enable "$SERVICE_NAME.service"
sudo systemctl start "$SERVICE_NAME.service"

# Wait a moment and check status
sleep 3

echo "📊 Service Status:"
sudo systemctl status "$SERVICE_NAME.service" --no-pager -l

echo ""
echo "✅ Installation Complete!"
echo ""
echo "📱 Management Commands:"
echo "   Status:   sudo systemctl status $SERVICE_NAME"
echo "   Start:    sudo systemctl start $SERVICE_NAME"
echo "   Stop:     sudo systemctl stop $SERVICE_NAME" 
echo "   Restart:  sudo systemctl restart $SERVICE_NAME"
echo "   Logs:     sudo journalctl -u $SERVICE_NAME -f"
echo "   Disable:  sudo systemctl disable $SERVICE_NAME"
echo ""
echo "🌐 Access your MyProxy at: http://$(hostname -I | cut -d' ' -f1):8080"
echo ""
echo "📝 The service will now:"
echo "   • Auto-start on boot"
echo "   • Auto-restart on crashes"  
echo "   • Persist device sessions"
echo "   • Log to systemd journal"

# Clean up
rm "$SERVICE_FILE_TEMP"