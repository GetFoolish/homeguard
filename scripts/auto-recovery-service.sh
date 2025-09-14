#!/bin/bash

# Auto-Recovery Service - Ensures management access on every boot
# Runs automatically to prevent SSH lockout

LOG_FILE="/var/log/homeguard-auto-recovery.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date)] HomeguardAuto-Recovery Service Starting..."

# Wait for network to be ready
sleep 10

# Ensure SSH listens on all interfaces
if grep -q "#ListenAddress 0.0.0.0" /etc/ssh/sshd_config; then
    sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
    systemctl reload ssh
    echo "[$(date)] SSH configured for all interfaces"
fi

# Activate HomeguardLAN if it exists
if nmcli connection show "HomeguardLAN" >/dev/null 2>&1; then
    nmcli connection up HomeguardLAN 2>/dev/null || echo "[$(date)] HomeguardLAN activation failed (might be normal)"
    echo "[$(date)] HomeguardLAN activation attempted"
fi

# Verify management IP is available
if ip addr show eth1 | grep -q "192.168.4.100"; then
    echo "[$(date)] ✅ Management IP active: 192.168.4.100"
else
    echo "[$(date)] ⚠️ Management IP not found - might be in sideline mode"
fi

echo "[$(date)] Auto-Recovery Service completed"
