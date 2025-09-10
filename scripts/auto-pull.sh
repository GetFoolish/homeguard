#!/bin/bash

# MyProxy Auto-Pull Service
# Checks GitHub every 5 minutes for new commits and triggers graceful restart

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOCK_FILE="/tmp/myproxy-autopull.lock"
LOG_FILE="/var/log/myproxy-autopull.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

# Prevent multiple instances running
if [[ -f "$LOCK_FILE" ]]; then
    LOCK_PID=$(cat "$LOCK_FILE")
    if kill -0 "$LOCK_PID" 2>/dev/null; then
        info "Auto-pull already running (PID: $LOCK_PID), exiting"
        exit 0
    else
        warn "Removing stale lock file"
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Cleanup on exit
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

cd "$PROJECT_DIR"

log "🔍 Checking for new commits..."

# Fetch latest changes from remote
if ! git fetch origin main 2>/dev/null; then
    error "Failed to fetch from remote repository"
    exit 1
fi

# Get current and remote commit hashes
LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

info "Local commit:  $LOCAL_HASH"
info "Remote commit: $REMOTE_HASH"

if [[ "$LOCAL_HASH" = "$REMOTE_HASH" ]]; then
    info "✅ Repository is up to date, no action needed"
    exit 0
fi

# New commits detected
log "🚀 New commits detected! Starting graceful update..."

# Get commit information
COMMITS_BEHIND=$(git rev-list --count HEAD..origin/main)
LATEST_COMMIT_MSG=$(git log origin/main -1 --pretty=format:"%s")

log "📝 Updates found:"
log "   • $COMMITS_BEHIND new commit(s)"
log "   • Latest: $LATEST_COMMIT_MSG"

# Check if we should update now or wait for maintenance window
CURRENT_HOUR=$(date +%H)
if [[ "$1" == "--force" ]] || [[ $CURRENT_HOUR -ge 2 && $CURRENT_HOUR -le 5 ]]; then
    log "🔄 Initiating graceful restart..."
    
    # Run graceful restart script
    if sudo "$SCRIPT_DIR/graceful-restart.sh"; then
        log "✅ Update completed successfully!"
        
        # Log successful update
        NEW_HASH=$(git rev-parse HEAD)
        log "📊 Update summary:"
        log "   • From: ${LOCAL_HASH:0:8}"
        log "   • To:   ${NEW_HASH:0:8}"
        log "   • Commits: $COMMITS_BEHIND"
        log "   • Message: $LATEST_COMMIT_MSG"
    else
        error "Graceful restart failed!"
        warn "MyProxy may be in an inconsistent state"
        exit 1
    fi
else
    log "⏰ New commits available, but waiting for maintenance window (2-5 AM)"
    log "   Current time: $(date '+%H:%M')"
    log "   Use --force to update immediately"
    log "   Updates will be applied automatically during next maintenance window"
fi

log "🏁 Auto-pull check completed"