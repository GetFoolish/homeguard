#!/bin/bash

# Pi deployment with expect for password automation
set -e

PI_IP="192.168.4.71"
PI_USER="raspberrypi"
PI_PASS="rp"

echo "🚀 Deploying MyProxy to Pi ($PI_IP)..."

# Test connection
if ! ping -c 2 "$PI_IP" >/dev/null 2>&1; then
    echo "❌ Cannot reach Pi at $PI_IP"
    exit 1
fi

echo "✅ Pi is reachable"

# Create deployment package
echo "📦 Creating deployment package..."
DEPLOY_DIR=$(mktemp -d)
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
echo "🔧 Commands:"
echo "   Status: sudo systemctl status myproxy-dual"
echo "   Logs: docker logs myproxy-gateway"
echo ""
INSTALL_EOF

chmod +x "$DEPLOY_DIR/install.sh"

# Transfer files using expect
echo "📤 Transferring files to Pi..."

export DEPLOY_DIR PI_USER PI_IP PI_PASS

expect << 'EOF'
set timeout 30
spawn scp -r $env(DEPLOY_DIR)/* $env(PI_USER)@$env(PI_IP):/home/raspberrypi/
expect {
    "password:" {
        send "$env(PI_PASS)\r"
        exp_continue
    }
    eof
}
EOF

if [ $? -ne 0 ]; then
    echo "❌ File transfer failed"
    rm -rf "$DEPLOY_DIR"
    exit 1
fi

echo "✅ Files transferred successfully"

# Run installation using expect
echo "🔧 Running installation on Pi..."

expect << 'EOF2'
set timeout 900
spawn ssh $env(PI_USER)@$env(PI_IP) {cd /home/raspberrypi && sudo bash install.sh}
expect {
    "password:" {
        send "$env(PI_PASS)\r"
        exp_continue
    }
    eof
}
EOF2

if [ $? -ne 0 ]; then
    echo "❌ Installation failed"
    rm -rf "$DEPLOY_DIR"
    exit 1
fi

# Cleanup
rm -rf "$DEPLOY_DIR"

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "🌐 Access MyProxy:"
echo "   Web Interface: http://$PI_IP"
echo ""
echo "🔧 SSH to Pi:"
echo "   ssh $PI_USER@$PI_IP"
echo "   password: rp"
echo ""
EOF