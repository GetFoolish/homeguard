# MyProxy - Network Traffic Authentication Gateway

**Python Environment**: Use `/Users/vandanchopra/Vandan_Personal_Folder/CODE_STUFF/Projects/myProxy/venv/bin/python`

## PROJECT STATUS ✅ DEPLOYMENT READY

### COMPLETED IMPLEMENTATION
- ✅ **Traffic Filtering**: Real iptables/netfilter blocking via FORWARD chain
- ✅ **TOTP Authentication**: Persistent sessions with database storage  
- ✅ **Docker Architecture**: Host networking mode for Pi deployment
- ✅ **Auto-Recovery**: Crash recovery, state restoration, auto-restart
- ✅ **Auto-Pull CI/CD**: GitHub monitoring with graceful updates every 5 minutes
- ✅ **Bridge Mode**: Auto-setup for inline deployment between routers

---

## ARCHITECTURE OVERVIEW

### Network Architecture - Inline Mode (Production)
```
ISP Router → Pi eth0 → Pi USB-ethernet → WiFi Router WAN
                ↓
           MyProxy Traffic Filtering
              (FORWARD chain)
                ↓
    ALL household traffic requires TOTP authentication
```

### Database Design (SQLite)
- **Device Management**: MAC addresses, IP tracking, authentication sessions  
- **TOTP Authentication**: 15min/30min/1hr/4hr access durations
- **Traffic Filtering**: Default DROP policy, whitelist authorized devices
- **Access Logging**: Authentication events, traffic attempts, system events

---

## DEPLOYMENT STATUS ✅

### Pi Configuration (192.168.4.100)
- ✅ **SSH Access**: `ssh -i ~/.ssh/myproxy_deploy raspberrypi@192.168.4.100`
- ✅ **Auto-Pull Service**: Deployed and active (checks GitHub every 5 minutes)
- ✅ **Docker Ready**: Host networking mode configured
- ✅ **Systemd Service**: Auto-boot with bridge mode detection

### Auto-Boot Sequence
```bash
1. Pi boots → systemd starts myproxy-dual.service
2. Check /etc/myproxy/mode.conf for MYPROXY_MODE
3. If bridge mode: Auto-run configure-bridge-mode.sh
4. Start MyProxy containers with proper networking
5. Traffic filtering active - blocks all unauthorized devices
```

---

## GOING INLINE - FINAL STEPS

### Phase 1: Prepare Hardware (2 mins)
1. **Connect USB Ethernet**: Plug into Pi USB port
2. **Physical Cabling**: ISP Router → Pi eth0 → Pi USB-eth → WiFi Router WAN
3. **Verify Connections**: Both ethernet ports should have link lights

### Phase 2: Switch to Bridge Mode (1 min)
```bash
# SSH to Pi
ssh -i ~/.ssh/myproxy_deploy raspberrypi@192.168.4.100

# Switch to bridge mode
echo "MYPROXY_MODE=bridge" | sudo tee /etc/myproxy/mode.conf

# Restart service (will auto-configure bridge networking)
sudo systemctl restart myproxy-dual

# Check status
sudo systemctl status myproxy-dual
```

### Phase 3: Verify Operation (2 mins)
```bash
# Test from household device (phone/laptop)
# 1. Try browsing - should be blocked
# 2. Go to http://192.168.4.100:8080 (Pi IP may change after bridge mode)
# 3. Enter TOTP code from Google Authenticator
# 4. Confirm internet access works
# 5. Verify YouTube is blocked for unauthenticated devices
```

---

## KEY FEATURES

### Security Model
- **Default Deny**: ALL internet traffic blocked until TOTP authentication
- **Device Tracking**: MAC address + IP address filtering via iptables
- **Session Management**: Timed access (15min to 4hr) with automatic expiry
- **Bypass Resistance**: MAC spoofing requires knowing both MAC + IP of authorized device

### Traffic Filtering (Production-Ready)
- **FORWARD Chain**: Filters all traffic passing through Pi (inline mode)
- **YouTube Blocking**: Comprehensive blocking (HTTP + HTTPS + DNS)
- **Whitelist Model**: Only explicitly authorized devices get internet access
- **Stateful Filtering**: Allows return traffic for established connections

### Management & Updates
- **Auto-Pull**: GitHub push → Pi updates automatically (2-5 AM maintenance window)
- **Graceful Restart**: Maintains network connectivity during updates (~25 seconds)
- **Web Interface**: http://Pi_IP:8080 for authentication and device management
- **Remote Access**: SSH-based management and troubleshooting

---

## CURRENT SESSION COMPLETION ✅

### ✅ FINAL TASKS COMPLETED
1. **Auto-Pull Service**: Deployed on Pi - monitors GitHub every 5 minutes
2. **Bridge Mode Scripts**: USB ethernet detection + networking auto-setup
3. **Systemd Integration**: Auto-boot with bridge mode configuration
4. **Production Ready**: Complete inline deployment preparation

### 🚀 READY FOR PRODUCTION DEPLOYMENT

**Physical Setup**: Connect USB ethernet + route cables
**Switch Mode**: Set `MYPROXY_MODE=bridge` in `/etc/myproxy/mode.conf`  
**Restart**: `sudo systemctl restart myproxy-dual`
**Result**: All household internet traffic requires TOTP authentication

---

## TROUBLESHOOTING

### Common Commands
```bash
# Check service status
sudo systemctl status myproxy-dual

# View logs
sudo journalctl -u myproxy-dual -f

# Check containers
docker ps

# View auto-pull logs  
tail -f /var/log/myproxy-autopull.log

# Manual update
cd /home/raspberrypi/myProxy && sudo ./scripts/auto-pull.sh --force
```

### Network Issues
```bash
# Check interfaces
ip link show

# Check iptables rules
sudo iptables -L -n -v

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
```

---

## PROJECT COMPLETE 🎉

**Status**: ✅ Ready for inline production deployment
**Next Step**: Physical setup + switch to bridge mode
**Estimated Time**: 5 minutes to go live

All household devices will require TOTP authentication for internet access.
Pi maintains internet connectivity for automatic updates via GitHub.