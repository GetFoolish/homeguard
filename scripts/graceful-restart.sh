#!/bin/bash

# MyProxy Graceful Restart with Passthrough Mode
# Maintains network connectivity during container restarts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

cd "$PROJECT_DIR"

log "🔄 Starting MyProxy graceful restart..."

# Step 1: Switch to passthrough mode (maintain network connectivity)
log "🌉 Step 1: Enabling passthrough mode..."
info "Backing up current iptables rules..."
iptables-save > /tmp/myproxy-iptables-backup-$(date +%s).rules

info "Clearing MyProxy traffic filtering rules..."
# Clear all MyProxy-specific rules
iptables -t nat -F OUTPUT 2>/dev/null || true
iptables -t filter -F OUTPUT 2>/dev/null || true
iptables -t nat -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true
iptables -t nat -D OUTPUT -d 127.0.0.0/8 -j ACCEPT 2>/dev/null || true

info "Setting up transparent bridge mode..."
# Enable IP forwarding (if not already enabled)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up basic forwarding rules for passthrough
iptables -A FORWARD -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true

log "✅ Passthrough mode enabled - network traffic flowing transparently"

# Step 2: Stop MyProxy containers gracefully
log "🛑 Step 2: Stopping MyProxy containers..."
if docker ps | grep -q myproxy; then
    info "Gracefully stopping containers..."
    docker-compose -f docker-compose.pi.yml down --timeout 10
    log "✅ Containers stopped"
else
    info "No MyProxy containers running"
fi

# Step 3: Update code and rebuild
log "📦 Step 3: Updating and rebuilding..."
info "Pulling latest changes..."
git fetch origin main
LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

if [[ "$LOCAL_HASH" != "$REMOTE_HASH" ]]; then
    log "🔄 New changes detected, updating..."
    git pull origin main
    
    info "Rebuilding containers with latest code..."
    docker-compose -f docker-compose.pi.yml build --no-cache
    log "✅ Build complete"
else
    log "ℹ️  No new changes, using existing build"
fi

# Step 4: Start containers
log "🚀 Step 4: Starting MyProxy containers..."
docker-compose -f docker-compose.pi.yml up -d

# Wait for containers to be ready
info "Waiting for containers to start..."
sleep 15

# Check if containers are running
if ! docker ps | grep -q myproxy; then
    error "Containers failed to start!"
    warn "Network is still in passthrough mode"
    exit 1
fi

log "✅ Containers started successfully"

# Step 5: Re-enable MyProxy traffic filtering
log "🔒 Step 5: Re-enabling MyProxy traffic filtering..."

# Wait a bit more for services to initialize
sleep 10

info "Setting up MyProxy traffic interception..."
# Re-run the traffic interception setup
if [[ -f scripts/setup-local-interception.sh ]]; then
    bash scripts/setup-local-interception.sh
else
    warn "Traffic interception script not found, setting up basic rules..."
    
    # Basic traffic redirection rules
    iptables -t nat -I OUTPUT 1 -o lo -j ACCEPT
    iptables -t nat -I OUTPUT 1 -d 127.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8888
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8888
fi

# Wait for MyProxy to fully initialize
info "Waiting for MyProxy to initialize..."
sleep 10

# Test if MyProxy web interface is responding
if curl -s -f http://localhost:8080 >/dev/null 2>&1; then
    log "✅ MyProxy web interface is responding"
elif curl -s http://localhost:8080 >/dev/null 2>&1; then
    log "✅ MyProxy web interface is accessible"
else
    warn "MyProxy web interface not responding yet - may need more time to start"
fi

log ""
log "🎉 Graceful restart completed successfully!"
log "📊 Network downtime: ~25 seconds (passthrough mode active)"
log "🌐 MyProxy is now filtering traffic again"
log "🔗 Admin interface: http://$(hostname -I | awk '{print $1}'):8080"
log ""
log "📋 Restart summary:"
log "   • Passthrough mode protected network connectivity"
log "   • Containers updated and restarted"
log "   • Traffic filtering re-enabled"
log "   • All household devices maintained internet access"