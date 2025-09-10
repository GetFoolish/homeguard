#!/bin/bash

# Simple Pi deployment - manual password entry
set -e

PI_IP="192.168.4.71"
PI_USER="raspberrypi"

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

# Create a tar archive for easy transfer
echo "📦 Creating deployment archive..."
cd "$DEPLOY_DIR"
tar -czf ../myproxy-deploy.tar.gz .
cd ..

echo "📤 Transferring deployment archive to Pi..."
echo "When prompted, enter password: rp"
scp myproxy-deploy.tar.gz "$PI_USER@$PI_IP:/home/raspberrypi/"

if [ $? -ne 0 ]; then
    echo "❌ File transfer failed"
    rm -rf "$DEPLOY_DIR" myproxy-deploy.tar.gz
    exit 1
fi

echo "✅ Archive transferred successfully"

# Run installation
echo "🔧 Running installation on Pi..."
echo "When prompted, enter password: rp"

ssh "$PI_USER@$PI_IP" << 'REMOTE_EOF'
cd /home/raspberrypi
echo "📦 Extracting deployment files..."
tar -xzf myproxy-deploy.tar.gz
echo "🚀 Starting installation..."
sudo bash install.sh
REMOTE_EOF

if [ $? -ne 0 ]; then
    echo "❌ Installation failed"
    rm -rf "$DEPLOY_DIR" myproxy-deploy.tar.gz
    exit 1
fi

# Cleanup
rm -rf "$DEPLOY_DIR" myproxy-deploy.tar.gz

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