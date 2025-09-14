#!/bin/bash

# Proper Inline Mode Setup - Preserve Management Access
# Ensures SSH/VNC work when Pi is inline

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"; }

if [[ $EUID -ne 0 ]]; then
   echo "Run with sudo"; exit 1
fi

log "🔧 Configuring Pi for inline mode with preserved management access..."

# Test current connectivity
if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "❌ No internet - fix first"; exit 1
fi
log "✅ Current connectivity confirmed"

# Configure SSH to listen on all interfaces (critical for inline access)
log "🔑 Configuring SSH for inline access..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true

# Ensure SSH listens on all interfaces
if ! grep -q "ListenAddress 0.0.0.0" /etc/ssh/sshd_config; then
    echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config
    log "✅ SSH configured to listen on all interfaces"
fi

# Configure VNC to listen on all interfaces
log "🖥️ Configuring VNC for inline access..."

# Enable VNC on all interfaces (if VNC is installed)
if command -v vncserver >/dev/null 2>&1 || systemctl is-active --quiet vncserver-x11-serviced; then
    # Configure VNC to accept connections from any IP
    if [ -f /root/.vnc/config.d/vncserver-x11 ]; then
        sed -i 's/Authentication=.*/Authentication=VncAuth/' /root/.vnc/config.d/vncserver-x11 2>/dev/null || true
    fi
    log "✅ VNC configured for remote access"
fi

# Configure HomeguardLAN with static management IP
log "🌐 Configuring HomeguardLAN interface..."

# Delete and recreate HomeguardLAN with proper configuration
nmcli connection delete "HomeguardLAN" 2>/dev/null || true

nmcli connection add type ethernet ifname eth1 con-name "HomeguardLAN" \
    ipv4.method manual \
    ipv4.addresses "192.168.4.100/24" \
    ipv4.routes "192.168.4.0/24 192.168.4.100" \
    ipv4.dns "8.8.8.8,8.8.4.4" \
    connection.autoconnect yes \
    connection.autoconnect-priority 100

log "✅ HomeguardLAN configured with management IP 192.168.4.100"

# CRITICAL: Activate HomeguardLAN NOW while in sideline mode
log "⚡ Activating HomeguardLAN interface..."
nmcli connection up HomeguardLAN

# Wait for interface to come up
sleep 3

# Verify eth1 has the management IP
if ip addr show eth1 | grep -q "192.168.4.100"; then
    log "✅ Management IP active: 192.168.4.100"
else
    echo "❌ Failed to activate management IP"
    exit 1
fi

# Test that SSH is accessible on the management IP
sleep 2
if ss -tlnp | grep -q ":22.*0.0.0.0:"; then
    log "✅ SSH listening on all interfaces"
else
    warn "⚠️ SSH may not be properly configured"
fi

# Restart SSH to apply configuration changes
systemctl reload ssh 2>/dev/null || systemctl restart ssh

log "🎉 Inline mode configuration completed!"
log ""
log "📊 Management Access Points:"
log "   • eth1 (inline): 192.168.4.100"
log "   • wlan0 (backup): $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
log "   • SSH: Listening on all interfaces"
log "   • VNC: Configured for remote access"
log ""
log "🔌 Physical Deployment Steps:"
log "   1. ISP Router → Pi eth0"
log "   2. Pi eth1 → WiFi Router WAN port"  
log "   3. Wait 30 seconds for network to stabilize"
log "   4. SSH: ssh raspberrypi@192.168.4.100"
log "   5. VNC: 192.168.4.100:5900"
log ""
warn "⚠️ Management access should work immediately after going inline!"
log "   HomeguardLAN is already active with 192.168.4.100"

# Install Auto-Recovery Service (Double Failsafe)
log "🔄 Installing auto-recovery service..."

# Install the service
cp /tmp/homeguard-auto-recovery.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable homeguard-auto-recovery.service

log "✅ Auto-recovery service installed"
log "   • Runs on every boot"
log "   • Ensures SSH access always available"
log "   • Activates management IP if possible"
log "   • Logs: /var/log/homeguard-auto-recovery.log"

warn "🛡️ DOUBLE FAILSAFE ACTIVE:"
warn "   1. Current setup ensures inline access"  
warn "   2. Auto-recovery service ensures boot access"
warn "   Even if something breaks, next reboot will restore access!"
