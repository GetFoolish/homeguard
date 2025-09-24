# HomeguardGuard Traffic Management Rules - Two-Chain Architecture

## Overview

This document specifies the new high-performance two-chain iptables architecture for HomeguardGuard that replaces the single `HOMEGUARD_FILTER` chain with an optimized `HOMEGUARD_ACCEPT` (fast path) and `HOMEGUARD_BLOCK` (slow path) system.

## Architecture Benefits

- **Performance**: Authenticated devices get fast-path processing (2 rules max)
- **Scalability**: Multiple authenticated devices don't slow down each other
- **Flexibility**: Easy mode switching without rebuilding entire ruleset
- **Maintainability**: Clear separation between allow/block logic

## Chain Structure

### FORWARD Chain Order
```
1. Management access rules (SSH/VNC/Web)
2. HOMEGUARD_ACCEPT jump (fast path for authenticated devices)
3. HOMEGUARD_BLOCK jump (slow path for unauthenticated devices)
4. Default transparent rules (LAN”WAN traffic flow)
```

### Custom Chains
- **HOMEGUARD_ACCEPT**: Contains allow rules for authenticated devices
- **HOMEGUARD_BLOCK**: Contains block rules for unauthenticated devices

## Mode Implementations

### Transparent Mode

**FORWARD Chain:**
```bash
1. ACCEPT tcp multiport dports 22,5900,8081                    # Management inbound
2. ACCEPT tcp multiport sports 22,5900,8081 ctstate ESTABLISHED # Management return
3. HOMEGUARD_ACCEPT ’ RETURN                                    # Fast path (empty)
4. HOMEGUARD_BLOCK ’ RETURN                                     # Slow path (empty)
5. ACCEPT -i eth1 -o eth0                                       # LAN ’ WAN traffic
6. ACCEPT -i eth0 -o eth1 ctstate ESTABLISHED                   # WAN ’ LAN return
```

**Chain Contents:**
```bash
HOMEGUARD_ACCEPT: RETURN (empty)
HOMEGUARD_BLOCK:  RETURN (empty)
Policy: ACCEPT
```

**Traffic Flow:** All traffic flows freely through rules 5-6 after empty chain returns.

### TOTP_FULL Mode (No Users Authenticated)

**FORWARD Chain:** (same structure as transparent)

**Chain Contents:**
```bash
HOMEGUARD_ACCEPT: RETURN (empty - no authenticated users)
HOMEGUARD_BLOCK:  DROP (blocks all non-management traffic)
Policy: DROP
```

**Traffic Flow:** Non-management traffic hits HOMEGUARD_BLOCK and gets dropped.

### TOTP_FULL Mode (User 192.168.2.61 Authenticated)

**FORWARD Chain:** (same structure)

**Chain Contents:**
```bash
HOMEGUARD_ACCEPT:
  1. ACCEPT -s 192.168.2.61 -j ACCEPT
  2. ACCEPT -d 192.168.2.61 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  3. RETURN

HOMEGUARD_BLOCK: DROP
```

**Traffic Flow:** 192.168.2.61 traffic hits fast path rules and gets accepted immediately. Other devices hit HOMEGUARD_BLOCK and get dropped.

## Implementation Commands

### Initial Setup (Run Once)

```bash
# Clean slate
sudo iptables -t filter -F FORWARD
sudo iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true
sudo iptables -t filter -X HOMEGUARD_ACCEPT 2>/dev/null || true
sudo iptables -t filter -X HOMEGUARD_BLOCK 2>/dev/null || true

# Create new chains
sudo iptables -t filter -N HOMEGUARD_ACCEPT
sudo iptables -t filter -N HOMEGUARD_BLOCK

# Build FORWARD chain structure
sudo iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,8081 -j ACCEPT
sudo iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,8081 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A FORWARD -j HOMEGUARD_ACCEPT
sudo iptables -t filter -A FORWARD -j HOMEGUARD_BLOCK
sudo iptables -t filter -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -t filter -A FORWARD -i eth0 -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

### Mode Switching

#### Switch to Transparent Mode
```bash
sudo iptables -t filter -F HOMEGUARD_ACCEPT
sudo iptables -t filter -F HOMEGUARD_BLOCK
sudo iptables -t filter -A HOMEGUARD_ACCEPT -j RETURN
sudo iptables -t filter -A HOMEGUARD_BLOCK -j RETURN
sudo iptables -t filter -P FORWARD ACCEPT
```

#### Switch to TOTP_FULL Mode
```bash
sudo iptables -t filter -F HOMEGUARD_ACCEPT
sudo iptables -t filter -F HOMEGUARD_BLOCK
sudo iptables -t filter -A HOMEGUARD_ACCEPT -j RETURN  # Empty initially
sudo iptables -t filter -A HOMEGUARD_BLOCK -j DROP    # Block all
sudo iptables -t filter -P FORWARD DROP
```

### Device Management

#### Authenticate Device (Grant Internet Access)
```bash
# Add device to fast path (both directions needed)
sudo iptables -t filter -I HOMEGUARD_ACCEPT 1 -s {DEVICE_IP} -j ACCEPT
sudo iptables -t filter -I HOMEGUARD_ACCEPT 2 -d {DEVICE_IP} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

#### Revoke Device Access (Block Internet)
```bash
# Remove device from fast path
sudo iptables -t filter -D HOMEGUARD_ACCEPT -s {DEVICE_IP} -j ACCEPT
sudo iptables -t filter -D HOMEGUARD_ACCEPT -d {DEVICE_IP} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## Code Integration Requirements

### HomeguardGuard Application Changes

#### 1. Phase Manager Updates

**File:** `src/homeguard/phases/phase_manager.py`

Replace single chain management with two-chain system:

```python
def setup_chains(self):
    """Create the two-chain architecture"""
    # Remove old chains
    run_iptables(["-t", "filter", "-X", "HOMEGUARD_FILTER"], ignore_errors=True)

    # Create new chains
    run_iptables(["-t", "filter", "-N", "HOMEGUARD_ACCEPT"])
    run_iptables(["-t", "filter", "-N", "HOMEGUARD_BLOCK"])

def apply_transparent_mode(self):
    """Configure chains for transparent mode"""
    # Empty chains with RETURN
    run_iptables(["-t", "filter", "-F", "HOMEGUARD_ACCEPT"])
    run_iptables(["-t", "filter", "-F", "HOMEGUARD_BLOCK"])
    run_iptables(["-t", "filter", "-A", "HOMEGUARD_ACCEPT", "-j", "RETURN"])
    run_iptables(["-t", "filter", "-A", "HOMEGUARD_BLOCK", "-j", "RETURN"])
    run_iptables(["-t", "filter", "-P", "FORWARD", "ACCEPT"])

def apply_totp_full_mode(self):
    """Configure chains for TOTP full blocking mode"""
    # Empty accept chain, add block rule
    run_iptables(["-t", "filter", "-F", "HOMEGUARD_ACCEPT"])
    run_iptables(["-t", "filter", "-F", "HOMEGUARD_BLOCK"])
    run_iptables(["-t", "filter", "-A", "HOMEGUARD_ACCEPT", "-j", "RETURN"])
    run_iptables(["-t", "filter", "-A", "HOMEGUARD_BLOCK", "-j", "DROP"])
    run_iptables(["-t", "filter", "-P", "FORWARD", "DROP"])
```

#### 2. Traffic Monitor Updates

**File:** `src/homeguard/network/traffic_monitor.py`

Update device allow/block methods:

```python
def allow_device_traffic(self, device_ip: str):
    """Add device to HOMEGUARD_ACCEPT fast path"""
    # Remove from block list first (idempotent)
    self.block_device_traffic(device_ip)

    # Add to accept list (both directions)
    run_iptables(["-t", "filter", "-I", "HOMEGUARD_ACCEPT", "1",
                  "-s", device_ip, "-j", "ACCEPT"])
    run_iptables(["-t", "filter", "-I", "HOMEGUARD_ACCEPT", "2",
                  "-d", device_ip, "-m", "conntrack",
                  "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

def block_device_traffic(self, device_ip: str):
    """Remove device from HOMEGUARD_ACCEPT fast path"""
    # Remove from accept list (both directions)
    run_iptables(["-t", "filter", "-D", "HOMEGUARD_ACCEPT",
                  "-s", device_ip, "-j", "ACCEPT"], ignore_errors=True)
    run_iptables(["-t", "filter", "-D", "HOMEGUARD_ACCEPT",
                  "-d", device_ip, "-m", "conntrack",
                  "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], ignore_errors=True)
```

#### 3. Web Interface Updates

**File:** `src/homeguard/web/app.py`

Update TOTP authentication success handler:

```python
@app.post("/authenticate")
async def authenticate_device(totp_code: str = Form(...)):
    client_info = get_client_info(request)
    device_ip = client_info['ip']

    if totp_manager.verify_code(totp_code):
        # Add to fast path instead of old HOMEGUARD_FILTER
        await traffic_monitor.allow_device_traffic(device_ip)

        # Set timer for revocation
        asyncio.create_task(revoke_after_timeout(device_ip, timeout_minutes))

        return RedirectResponse(url="/", status_code=302)
```

#### 4. Emergency Restore Script Updates

**File:** `scripts/emergency-restore.sh`

Update to use new two-chain structure for emergency transparent mode.

## Testing Scenarios

### Performance Testing
1. **Baseline**: Test speed in transparent mode with new architecture
2. **Single user**: Test speed with one device in HOMEGUARD_ACCEPT
3. **Multiple users**: Test speed with multiple devices authenticated
4. **Mode switching**: Verify no performance degradation during switches

### Functional Testing
1. **Transparent mode**: All devices have internet access
2. **TOTP_FULL mode**: All devices blocked initially
3. **Authentication**: Device gets fast-path internet after TOTP
4. **Revocation**: Device loses internet when removed from fast-path
5. **Management access**: SSH/VNC/Web always work in all modes

## Migration Plan

1. **Backup current rules**: `iptables-save > /tmp/homeguard_backup.rules`
2. **Update HomeguardGuard code** with new two-chain logic
3. **Test in development environment** with new architecture
4. **Deploy to production** with rollback plan
5. **Verify performance improvements** meet expectations

## Rollback Plan

If issues occur, restore original single-chain architecture:
```bash
# Restore single chain
sudo iptables -t filter -F FORWARD
sudo iptables -t filter -X HOMEGUARD_ACCEPT
sudo iptables -t filter -X HOMEGUARD_BLOCK
sudo iptables -t filter -N HOMEGUARD_FILTER

# Restore original FORWARD structure
sudo iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,8081 -j ACCEPT
sudo iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,8081 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A FORWARD -j HOMEGUARD_FILTER
```

## Expected Performance Improvements

- **Authenticated devices**: 5-10x faster packet processing
- **System CPU**: 50%+ reduction in kernel time
- **Throughput**: Should achieve near line-rate speeds (35-40 Mbps)
- **Latency**: Reduced packet processing delay for authenticated traffic

## Notes for Implementation

1. **Preserve existing functionality**: All current features should work unchanged
2. **Maintain compatibility**: Mode switching via `set-mode.sh` should work
3. **Error handling**: Graceful fallback if chain operations fail
4. **Logging**: Log chain operations for debugging
5. **Testing**: Thoroughly test mode transitions and device auth/revoke cycles