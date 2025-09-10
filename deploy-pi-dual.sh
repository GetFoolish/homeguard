#!/bin/bash

# MyProxy Dual-Mode Raspberry Pi Deployment Script
# Deploys MyProxy with support for both Access Point and Bridge modes
# Automatically detects best mode or allows manual selection

set -e

# Configuration
PI_IP="192.168.4.71"  # From CLAUDE.md
PROJECT_DIR="/home/pi/myProxy"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    echo "MyProxy Dual-Mode Raspberry Pi Deployment"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --mode MODE     Force deployment mode (ap|bridge|auto)"
    echo "  --pi-ip IP      Raspberry Pi IP address (default: $PI_IP)"
    echo "  --local         Deploy on local machine (skip SSH)"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Auto-detect mode and deploy"
    echo "  $0 --mode ap         # Force Access Point mode"
    echo "  $0 --mode bridge     # Force Bridge mode"
    echo "  $0 --pi-ip 192.168.1.100  # Use different Pi IP"
    echo ""
    echo "Modes:"
    echo "  ap      - Access Point mode (Pi creates WiFi hotspot)"
    echo "  bridge  - Bridge mode (Pi between ISP router and WiFi router)"
    echo "  auto    - Automatically detect best mode based on hardware"
    echo ""
}

# Function to parse command line arguments
parse_arguments() {
    FORCED_MODE=""
    LOCAL_DEPLOY=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode)
                FORCED_MODE="$2"
                if [ "$FORCED_MODE" != "ap" ] && [ "$FORCED_MODE" != "bridge" ] && [ "$FORCED_MODE" != "auto" ]; then
                    log_error "Invalid mode: $FORCED_MODE (must be ap, bridge, or auto)"
                    exit 1
                fi
                shift 2
                ;;
            --pi-ip)
                PI_IP="$2"
                shift 2
                ;;
            --local)
                LOCAL_DEPLOY=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    export FORCED_MODE LOCAL_DEPLOY PI_IP
}

# Function to test Pi connectivity
test_pi_connection() {
    if [ "$LOCAL_DEPLOY" = true ]; then
        log "🏠 Local deployment mode - skipping Pi connectivity test"
        return 0
    fi
    
    log "🔍 Testing connection to Raspberry Pi ($PI_IP)..."
    
    # Test ping first
    if ! ping -c 2 "$PI_IP" >/dev/null 2>&1; then
        log_error "Cannot ping Raspberry Pi at $PI_IP"
        log_error "Please check:"
        log_error "  1. Pi is powered on and connected to network"
        log_error "  2. IP address is correct (use --pi-ip to specify)"
        log_error "  3. Network connectivity"
        return 1
    fi
    
    log_success "Pi is reachable at $PI_IP"
    
    # Test SSH connection
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes pi@"$PI_IP" 'echo "SSH OK"' >/dev/null 2>&1; then
        log_warning "SSH connection failed - may need to set up SSH keys"
        log "To set up SSH access:"
        log "  1. ssh-copy-id pi@$PI_IP"
        log "  2. Or enable SSH: sudo systemctl enable ssh && sudo systemctl start ssh"
        return 1
    fi
    
    log_success "SSH connection to Pi working"
    return 0
}

# Function to prepare deployment files
prepare_deployment_files() {
    log "📦 Preparing deployment files..."
    
    # Create temporary deployment directory
    DEPLOY_DIR=$(mktemp -d)
    
    # Copy necessary files
    cp -r "$SCRIPT_DIR/scripts" "$DEPLOY_DIR/"
    cp "$SCRIPT_DIR/docker-compose.pi.yml" "$DEPLOY_DIR/"
    cp "$SCRIPT_DIR/myproxy-dual.service" "$DEPLOY_DIR/"
    cp "$SCRIPT_DIR/Dockerfile" "$DEPLOY_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$DEPLOY_DIR/"
    cp -r "$SCRIPT_DIR/src" "$DEPLOY_DIR/"
    
    # Create TOTP secrets file if it doesn't exist
    if [ ! -f "$SCRIPT_DIR/totp_secrets.json" ]; then
        log "🔑 Creating default TOTP secrets file..."
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
    else
        cp "$SCRIPT_DIR/totp_secrets.json" "$DEPLOY_DIR/"
    fi
    
    # Create deployment script for Pi
    cat > "$DEPLOY_DIR/install-on-pi.sh" <<'EOF'
#!/bin/bash
set -e

PROJECT_DIR="/home/pi/myProxy"
FORCED_MODE="$1"

echo "🥧 Installing MyProxy on Raspberry Pi..."

# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker pi
    rm get-docker.sh
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "🐳 Installing Docker Compose..."
    sudo apt-get install -y docker-compose
fi

# Create project directory
sudo mkdir -p "$PROJECT_DIR"
sudo chown -R pi:pi "$PROJECT_DIR"

# Copy files to project directory
cp -r * "$PROJECT_DIR/"
chmod +x "$PROJECT_DIR"/scripts/pi-deployment/*.sh

# Install systemd service
sudo cp "$PROJECT_DIR/myproxy-dual.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable myproxy-dual

# Create configuration directory
sudo mkdir -p /etc/myproxy

# Run mode detection and configuration
cd "$PROJECT_DIR/scripts/pi-deployment"
if [ -n "$FORCED_MODE" ] && [ "$FORCED_MODE" != "auto" ]; then
    echo "MODE=\"$FORCED_MODE\"" | sudo tee /etc/myproxy/mode.conf > /dev/null
    echo "🎯 Forced mode: $FORCED_MODE"
else
    echo "🤖 Auto-detecting best mode..."
    sudo ./detect-mode.sh > /dev/null
fi

# Read detected mode
source /etc/myproxy/mode.conf
echo "✅ Selected mode: $MODE"

# Configure network for selected mode
if [ "$MODE" = "ap" ]; then
    echo "📡 Configuring Access Point mode..."
    sudo ./configure-ap.sh
elif [ "$MODE" = "bridge" ]; then
    echo "🌉 Configuring Bridge mode..."
    sudo ./configure-bridge.sh
fi

# Build Docker image
cd "$PROJECT_DIR"
echo "🐳 Building MyProxy Docker image..."
docker-compose -f docker-compose.pi.yml build

# Start services
echo "🚀 Starting MyProxy services..."
sudo systemctl start myproxy-dual

echo ""
echo "🎉 MyProxy installation complete!"
echo ""
echo "📊 Status:"
echo "   Mode: $MODE"
echo "   IP: $(hostname -I | awk '{print $1}')"
echo "   Web: http://$(hostname -I | awk '{print $1}')"
echo ""
echo "🔧 Management:"
echo "   Status: sudo systemctl status myproxy-dual"
echo "   Logs: docker logs myproxy-gateway"
echo "   Switch mode: sudo /home/pi/myProxy/scripts/pi-deployment/switch-mode.sh [ap|bridge]"
echo ""
EOF
    
    chmod +x "$DEPLOY_DIR/install-on-pi.sh"
    
    export DEPLOY_DIR
    log_success "Deployment files prepared in: $DEPLOY_DIR"
}

# Function to transfer files to Pi
transfer_files_to_pi() {
    if [ "$LOCAL_DEPLOY" = true ]; then
        log "🏠 Local deployment - copying files directly..."
        sudo mkdir -p "$PROJECT_DIR"
        sudo cp -r "$DEPLOY_DIR"/* "$PROJECT_DIR/"
        sudo chown -R "$USER:$USER" "$PROJECT_DIR"
        return 0
    fi
    
    log "📤 Transferring files to Pi ($PI_IP)..."
    
    # Create project directory on Pi
    ssh pi@"$PI_IP" "mkdir -p $PROJECT_DIR"
    
    # Transfer files
    scp -r "$DEPLOY_DIR"/* pi@"$PI_IP":"$PROJECT_DIR/"
    
    log_success "Files transferred to Pi"
}

# Function to run installation on Pi
run_pi_installation() {
    local MODE_ARG=""
    if [ -n "$FORCED_MODE" ]; then
        MODE_ARG="$FORCED_MODE"
    fi
    
    if [ "$LOCAL_DEPLOY" = true ]; then
        log "🏠 Running local installation..."
        cd "$PROJECT_DIR"
        sudo bash install-on-pi.sh "$MODE_ARG"
    else
        log "🥧 Running installation on Pi..."
        ssh pi@"$PI_IP" "cd $PROJECT_DIR && sudo bash install-on-pi.sh '$MODE_ARG'"
    fi
}

# Function to show final status
show_final_status() {
    log "📊 Deployment Summary"
    echo ""
    
    if [ "$LOCAL_DEPLOY" = true ]; then
        log_success "🎉 MyProxy deployed locally!"
        FINAL_IP=$(hostname -I | awk '{print $1}')
    else
        log_success "🎉 MyProxy deployed on Raspberry Pi!"
        FINAL_IP="$PI_IP"
    fi
    
    echo ""
    echo "🌐 Access MyProxy:"
    echo "   Web Interface: http://$FINAL_IP"
    echo "   Admin Panel: http://$FINAL_IP:8080"
    echo ""
    
    if [ "$LOCAL_DEPLOY" = false ]; then
        echo "🔧 Remote Management:"
        echo "   SSH: ssh pi@$PI_IP"
        echo "   Status: ssh pi@$PI_IP 'sudo systemctl status myproxy-dual'"
        echo "   Logs: ssh pi@$PI_IP 'docker logs myproxy-gateway'"
        echo ""
    fi
    
    echo "📋 Mode Management:"
    echo "   Switch to AP: sudo $PROJECT_DIR/scripts/pi-deployment/switch-mode.sh ap"
    echo "   Switch to Bridge: sudo $PROJECT_DIR/scripts/pi-deployment/switch-mode.sh bridge"
    echo "   Auto-detect: sudo $PROJECT_DIR/scripts/pi-deployment/switch-mode.sh auto"
    echo "   Status: sudo $PROJECT_DIR/scripts/pi-deployment/switch-mode.sh status"
    echo ""
    
    log_success "🚀 Deployment completed successfully!"
}

# Function to cleanup
cleanup() {
    if [ -n "$DEPLOY_DIR" ] && [ -d "$DEPLOY_DIR" ]; then
        log "🧹 Cleaning up temporary files..."
        rm -rf "$DEPLOY_DIR"
    fi
}

# Main deployment function
main() {
    log "🚀 MyProxy Dual-Mode Pi Deployment Starting..."
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Parse arguments
    parse_arguments "$@"
    
    # Show deployment info
    echo ""
    log "📋 Deployment Configuration:"
    echo "   Target: $([ "$LOCAL_DEPLOY" = true ] && echo "Local machine" || echo "Raspberry Pi ($PI_IP)")"
    echo "   Mode: $([ -n "$FORCED_MODE" ] && echo "$FORCED_MODE (forced)" || echo "auto-detect")"
    echo ""
    
    # Run deployment steps
    if [ "$LOCAL_DEPLOY" = false ]; then
        test_pi_connection
    fi
    
    prepare_deployment_files
    transfer_files_to_pi
    run_pi_installation
    show_final_status
    
    log_success "🎉 Dual-mode MyProxy deployment completed!"
}

# Run main function if script is executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi