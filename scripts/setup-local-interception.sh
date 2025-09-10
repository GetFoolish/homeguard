#!/bin/bash

# MyProxy Local Traffic Interception Setup
# Routes Pi's own traffic through MyProxy containers for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
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

log "Setting up MyProxy local traffic interception..."

# Create mode configuration for local testing
log "Creating local testing mode configuration..."
mkdir -p /etc/myproxy

cat > /etc/myproxy/mode.conf << EOF
# MyProxy Mode Configuration
# Generated for local testing mode on $(date)

MYPROXY_MODE=local
WAN_INTERFACE=eth0
LAN_INTERFACE=lo
MYPROXY_GATEWAY_IP=127.0.0.1
EOF

log "Mode configuration created at /etc/myproxy/mode.conf"

# Set up iptables rules to redirect traffic to MyProxy
log "Setting up iptables rules for local traffic interception..."

# Backup existing iptables rules
iptables-save > /tmp/iptables-backup-$(date +%s).rules

# Create new chain for MyProxy
iptables -t nat -N MYPROXY_LOCAL 2>/dev/null || true
iptables -t filter -N MYPROXY_FILTER 2>/dev/null || true

# Exempt localhost traffic from redirection (CRITICAL for web server)
iptables -t nat -I OUTPUT 1 -o lo -j ACCEPT
iptables -t nat -I OUTPUT 1 -d 127.0.0.0/8 -j ACCEPT

# Redirect HTTP traffic to proxy (port 8888)
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8888
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8888

# Allow traffic to MyProxy admin interface
iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT

# Log redirected traffic
iptables -A OUTPUT -p tcp --dport 8888 -j LOG --log-prefix "MYPROXY_LOCAL: "

log "iptables rules configured for local traffic interception"

# Configure environment variables for Docker
log "Setting up environment for Docker..."

export MYPROXY_MODE=local
export WAN_INTERFACE=eth0
export LAN_INTERFACE=lo
export MYPROXY_GATEWAY_IP=127.0.0.1

# Create systemd environment file
cat > /etc/systemd/system/myproxy-dual.service.d/local.conf << EOF
[Service]
Environment="MYPROXY_MODE=local"
Environment="WAN_INTERFACE=eth0"
Environment="LAN_INTERFACE=lo"
Environment="MYPROXY_GATEWAY_IP=127.0.0.1"
EOF

log "Environment configured for local testing"

# Ensure Docker is running
if ! systemctl is-active --quiet docker; then
    log "Starting Docker service..."
    systemctl start docker
fi

log "Local traffic interception setup complete!"
log ""
log "Next steps:"
log "1. Start MyProxy containers: cd $PROJECT_DIR && docker-compose -f docker-compose.pi.yml up -d"
log "2. Test unauthenticated access: curl google.com (should fail)"
log "3. Access admin interface: curl localhost:8080 (should work)"
log "4. Authenticate via web interface"
log "5. Test authenticated access: curl google.com (should work)"
log ""
log "To restore original iptables: iptables-restore < /tmp/iptables-backup-*.rules"