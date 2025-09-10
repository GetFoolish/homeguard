#!/bin/bash

# MyProxy Auto-Pull Installation Script
# Sets up cron job for automatic updates

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

log "🔧 Installing MyProxy Auto-Pull Service..."

# Create log directory
info "Creating log directory..."
mkdir -p /var/log
touch /var/log/myproxy-autopull.log
chown raspberrypi:raspberrypi /var/log/myproxy-autopull.log

# Install cron job for pi user
info "Setting up cron job..."
CRON_JOB="*/5 * * * * cd $PROJECT_DIR && $SCRIPT_DIR/auto-pull.sh >> /var/log/myproxy-autopull.log 2>&1"

# Remove existing MyProxy auto-pull cron jobs
crontab -u raspberrypi -l 2>/dev/null | grep -v "auto-pull.sh" | crontab -u raspberrypi - 2>/dev/null || true

# Add new cron job
(crontab -u raspberrypi -l 2>/dev/null; echo "$CRON_JOB") | crontab -u raspberrypi -

log "✅ Auto-pull service installed successfully!"
log ""
log "📋 Configuration:"
log "   • Checks for updates: Every 5 minutes"
log "   • Updates during: 2-5 AM (maintenance window)"
log "   • Force update: ./scripts/auto-pull.sh --force"
log "   • View logs: tail -f /var/log/myproxy-autopull.log"
log ""
log "🔄 Auto-pull service is now active!"
log "   Push changes to GitHub → Pi updates automatically"
log "   Graceful restart maintains network connectivity"
log ""
log "📊 Service status:"
log "   • Cron job: Active (every 5 minutes)"
log "   • Log file: /var/log/myproxy-autopull.log"
log "   • Lock file: /tmp/myproxy-autopull.lock (when running)"

# Show current crontab for verification
info "Current cron jobs for raspberrypi user:"
crontab -u raspberrypi -l | grep -E "(auto-pull|myproxy)" || echo "   No MyProxy cron jobs found"