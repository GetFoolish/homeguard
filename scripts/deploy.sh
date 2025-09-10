#!/bin/bash

# MyProxy Deployment Script for Raspberry Pi
# Can be run locally or via GitHub Actions

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

# Check if we're on the Pi or deploying remotely
if [[ "${HOSTNAME}" == "raspberrypi" ]] || [[ "${USER}" == "pi" ]]; then
    LOCAL_DEPLOY=true
    log "Detected Raspberry Pi - running local deployment"
else
    LOCAL_DEPLOY=false
    log "Running remote deployment to Raspberry Pi"
fi

cd "$PROJECT_DIR"

# Stop existing service if running
log "Stopping existing MyProxy service..."
if $LOCAL_DEPLOY; then
    sudo systemctl stop myproxy-dual 2>/dev/null || true
else
    ssh raspberrypi@192.168.4.100 'sudo systemctl stop myproxy-dual' 2>/dev/null || true
fi

# Pull latest changes (if git repo)
if [[ -d .git ]]; then
    log "Pulling latest changes from git..."
    if $LOCAL_DEPLOY; then
        git pull origin main || warn "Git pull failed - continuing with current code"
    else
        ssh raspberrypi@192.168.4.100 "cd myProxy && git pull origin main" || warn "Git pull failed - continuing with current code"
    fi
fi

# Build containers
log "Building MyProxy containers..."
if $LOCAL_DEPLOY; then
    docker-compose -f docker-compose.pi.yml build --no-cache
else
    ssh raspberrypi@192.168.4.100 "cd myProxy && docker-compose -f docker-compose.pi.yml build --no-cache"
fi

# Install/update systemd service
log "Installing systemd service..."
if $LOCAL_DEPLOY; then
    sudo cp myproxy-dual.service /etc/systemd/system/
    sudo mkdir -p /etc/systemd/system/myproxy-dual.service.d
    sudo cp myproxy-dual.service.d/local.conf /etc/systemd/system/myproxy-dual.service.d/
    sudo systemctl daemon-reload
else
    scp myproxy-dual.service raspberrypi@192.168.4.100:/tmp/
    scp -r myproxy-dual.service.d raspberrypi@192.168.4.100:/tmp/
    ssh raspberrypi@192.168.4.100 'sudo cp /tmp/myproxy-dual.service /etc/systemd/system/ && sudo mkdir -p /etc/systemd/system/myproxy-dual.service.d && sudo cp /tmp/myproxy-dual.service.d/local.conf /etc/systemd/system/myproxy-dual.service.d/ && sudo systemctl daemon-reload'
fi

# Set up local traffic interception (Pi only)
if $LOCAL_DEPLOY; then
    log "Setting up local traffic interception..."
    sudo ./scripts/setup-local-interception.sh
fi

# Start service
log "Starting MyProxy service..."
if $LOCAL_DEPLOY; then
    sudo systemctl enable myproxy-dual
    sudo systemctl start myproxy-dual
else
    ssh raspberrypi@192.168.4.100 'sudo systemctl enable myproxy-dual && sudo systemctl start myproxy-dual'
fi

# Wait for service to start
log "Waiting for service to start..."
sleep 10

# Check service status
log "Checking service status..."
if $LOCAL_DEPLOY; then
    sudo systemctl status myproxy-dual --no-pager
else
    ssh raspberrypi@192.168.4.100 'sudo systemctl status myproxy-dual --no-pager'
fi

log "Deployment complete!"
log ""
if $LOCAL_DEPLOY; then
    log "MyProxy is now running in local testing mode"
    log "Admin interface: http://localhost:8080"
    log "Test commands:"
    log "  curl google.com (should be intercepted)"
    log "  curl localhost:8080 (admin interface)"
else
    log "MyProxy deployed to Raspberry Pi"
    log "Admin interface: http://192.168.4.100:8080"
    log "SSH access: ssh raspberrypi@192.168.4.100"
fi