#!/usr/bin/expect -f

set PI_IP "192.168.4.71"
set PI_USER "raspberrypi"
set PI_PASSWORD "rp"

# Create deployment package
spawn bash -c {
    echo "📦 Creating deployment package..."
    DEPLOY_DIR=$(mktemp -d)
    cd /Users/vandanchopra/Vandan_Personal_Folder/CODE_STUFF/Projects/myProxy
    cp -r scripts "$DEPLOY_DIR/"
    cp docker-compose.pi.yml "$DEPLOY_DIR/"  
    cp myproxy-dual.service "$DEPLOY_DIR/"
    cp Dockerfile "$DEPLOY_DIR/"
    cp requirements.txt "$DEPLOY_DIR/"
    cp -r src "$DEPLOY_DIR/"

    # Create TOTP secrets
    cat > "$DEPLOY_DIR/totp_secrets.json" <<EOF
{
  "15min": "JBSWY3DPEHPK3PXP",
  "30min": "JBSWY3DPEHPK3PXQ", 
  "1hr": "JBSWY3DPEHPK3PXR",
  "2hr": "JBSWY3DPEHPK3PXS",
  "4hr": "JBSWY3DPEHPK3PXT",
  "24hr": "JBSWY3DPEHPK3PXU",
  "1week": "JBSWY3DPEHPK3PXV",
  "forever": "JBSWY3DPEHPK3PXW"
}
EOF

    # Create install script
    cat > "$DEPLOY_DIR/install.sh" <<'INSTALL_EOF'
#!/bin/bash
set -e

echo "🥧 Installing MyProxy on Raspberry Pi..."

# Update system
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Docker
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker raspberrypi
    rm get-docker.sh
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "🐳 Installing Docker Compose..."
    sudo apt-get install -y docker-compose
fi

# Create project directory
PROJECT_DIR="/home/raspberrypi/myProxy"
mkdir -p "$PROJECT_DIR"

# Copy files
cp -r * "$PROJECT_DIR/"
chmod +x "$PROJECT_DIR"/scripts/pi-deployment/*.sh

# Create config directory
sudo mkdir -p /etc/myproxy

# Auto-detect mode
cd "$PROJECT_DIR/scripts/pi-deployment"
echo "🤖 Detecting best mode..."
sudo ./detect-mode.sh

# Read detected mode
source /etc/myproxy/mode.conf
echo "✅ Selected mode: $MODE"

# Configure for detected mode
if [ "$MODE" = "ap" ]; then
    echo "📡 Configuring Access Point mode..."
    sudo ./configure-ap.sh
elif [ "$MODE" = "bridge" ]; then
    echo "🌉 Configuring Bridge mode..."  
    sudo ./configure-bridge.sh
fi

# Install systemd service
cd "$PROJECT_DIR"
sudo cp myproxy-dual.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable myproxy-dual

# Build and start
echo "🐳 Building MyProxy..."
docker-compose -f docker-compose.pi.yml build

echo "🚀 Starting MyProxy..."
sudo systemctl start myproxy-dual

echo ""
echo "🎉 MyProxy installation complete!"
echo ""
echo "📊 Access MyProxy:"
echo "   Web: http://$(hostname -I | awk '{print $1}')"
echo ""
INSTALL_EOF

    chmod +x "$DEPLOY_DIR/install.sh"

    # Create tar archive
    echo "📦 Creating deployment archive..."
    cd "$DEPLOY_DIR"
    tar -czf /tmp/myproxy-deploy.tar.gz .
    echo "/tmp/myproxy-deploy.tar.gz"
}
expect eof

# Transfer the archive
puts "📤 Transferring deployment archive to Pi..."
spawn scp /tmp/myproxy-deploy.tar.gz $PI_USER@$PI_IP:/home/raspberrypi/
expect "password:"
send "$PI_PASSWORD\r"
expect eof

# Run installation
puts "🔧 Running installation on Pi..."
spawn ssh $PI_USER@$PI_IP
expect "password:"
send "$PI_PASSWORD\r"
expect "$ "

send "cd /home/raspberrypi\r"
expect "$ "

send "echo '📦 Extracting deployment files...'\r"
expect "$ "

send "tar -xzf myproxy-deploy.tar.gz\r"
expect "$ "

send "echo '🚀 Starting installation...'\r"
expect "$ "

send "sudo bash install.sh\r"
expect {
    "password for raspberrypi:" {
        send "$PI_PASSWORD\r"
        exp_continue
    }
    "$ " {
        puts "Installation completed!"
    }
}

send "exit\r"
expect eof

puts ""
puts "🎉 Deployment complete!"
puts ""
puts "🌐 Access MyProxy:"
puts "   Web Interface: http://$PI_IP"
puts ""