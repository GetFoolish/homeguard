#!/bin/bash

# MyProxy Local Testing Script
# Verifies that MyProxy is intercepting traffic correctly

set -e

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

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

fail() {
    echo -e "${RED}❌ $1${NC}"
}

log "Starting MyProxy local functionality test..."

# Check if MyProxy service is running
log "Checking MyProxy service status..."
if systemctl is-active --quiet myproxy-dual; then
    success "MyProxy service is running"
else
    fail "MyProxy service is not running"
    error "Run: sudo systemctl start myproxy-dual"
    exit 1
fi

# Check if containers are running
log "Checking Docker containers..."
RUNNING_CONTAINERS=$(docker ps --filter "name=myproxy" --format "table {{.Names}}\t{{.Status}}" | tail -n +2)
if [[ -n "$RUNNING_CONTAINERS" ]]; then
    success "MyProxy containers are running:"
    echo "$RUNNING_CONTAINERS"
else
    fail "No MyProxy containers running"
    exit 1
fi

# Test admin interface access
log "Testing admin interface access..."
if curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
    success "Admin interface is accessible at http://localhost:8080"
elif curl -s -f http://localhost:8080 >/dev/null 2>&1; then
    success "Admin interface is accessible at http://localhost:8080 (no /health endpoint)"
else
    fail "Admin interface is not accessible"
    warn "Check if MyProxy is listening on port 8080"
fi

# Test HTTP proxy functionality
log "Testing HTTP proxy functionality..."
if curl -s --proxy http://localhost:8888 http://httpbin.org/ip >/dev/null 2>&1; then
    success "HTTP proxy is working on port 8888"
else
    warn "HTTP proxy test failed - this may be expected if not authenticated"
fi

# Test DNS resolution
log "Testing DNS resolution..."
if nslookup google.com >/dev/null 2>&1; then
    success "DNS resolution is working"
else
    warn "DNS resolution issues detected"
fi

# Check iptables rules
log "Checking iptables rules for traffic redirection..."
if iptables -t nat -L OUTPUT | grep -q "REDIRECT.*8888"; then
    success "Traffic redirection rules are active"
else
    warn "No traffic redirection rules found"
    info "Run setup script: sudo ./scripts/setup-local-interception.sh"
fi

# Test blocked domain (should fail if unauthenticated)
log "Testing blocked domain access (youtube.com)..."
if timeout 5 curl -s youtube.com >/dev/null 2>&1; then
    warn "youtube.com is accessible (may indicate authentication is active)"
else
    success "youtube.com is blocked (expected for unauthenticated access)"
fi

# Test regular domain access
log "Testing regular domain access (google.com)..."
if timeout 5 curl -s google.com >/dev/null 2>&1; then
    info "google.com is accessible"
else
    info "google.com is blocked (depends on authentication status)"
fi

log ""
log "Test completed! Summary:"
log "🌐 Admin interface: http://localhost:8080"
log "🔒 To authenticate: Open admin interface and enter TOTP code"
log "📊 Service logs: sudo journalctl -u myproxy-dual -f"
log "🐳 Container logs: docker-compose -f docker-compose.pi.yml logs -f"
log ""
log "Manual testing commands:"
log "  curl google.com          # Should be intercepted"
log "  curl localhost:8080      # Admin interface"
log "  curl youtube.com         # Should be blocked"