# MyProxy - Network Traffic Authentication Gateway

**Python Environment**: Use `/Users/vandanchopra/Vandan_Personal_Folder/CODE_STUFF/Projects/myProxy/venv/bin/python`

## PROJECT STATUS: 🚧 PRE-INLINE DEVELOPMENT REQUIRED

### CURRENT SITUATION
- ✅ **Basic System**: TOTP authentication, iptables filtering, Docker deployment
- ✅ **Pi Deployment**: Auto-pull, bridge scripts, systemd integration
- ❌ **Inline Ready**: Missing phased rollout, dual networking, enhanced filtering
- **Timeline**: 2-3 weeks development + 1 week gradual rollout

### CRITICAL REQUIREMENTS BEFORE INLINE
- Phase management system (6-phase rollout)
- Enhanced traffic filtering (keywords, URLs, Google Sheets)
- Pi self-exemption from filtering rules
- Dual IP networking configuration
- Separate content blocked splash screens
- Comprehensive testing in current environment

---

## PRE-INLINE REQUIREMENTS ANALYSIS

### SESSION CONTEXT (2025-09-10)
Analysis of 6 critical questions for safe inline deployment:

### 1. **Pi IP Address Strategy**
**Question**: What will the Pi's IP be when inline between ISP router (192.168.1.1) and WiFi router (192.168.4.1)?

**Answer**: 
- **Primary IP**: 192.168.1.100 (static on WAN/eth0 interface)
- **Backup IP**: 192.168.4.100 (keep WiFi for emergency access)
- **Configuration**: Static IP assignment in bridge mode script

### 2. **SSH/VNC Access Preservation**
**Question**: How to ensure SSH/VNC continues working after inline deployment?

**Answer**: ✅ Will work automatically
- SSH to 192.168.1.100 (primary access)
- SSH to 192.168.4.100 (backup access via WiFi)
- Both IPs will be accessible from network segments

### 3. **6-Phase Rollout Implementation**
**Question**: Gradual rollout from transparent bridge to full TOTP authentication

**Answer**: Requires new phase management system:
- Phase 1: Transparent bridge (no blocking)
- Phase 2: Traffic monitoring only
- Phase 3: Block NDTV.com only
- Phase 4: Block "mickey and jj" keywords
- Phase 5: Google Sheets integration
- Phase 6: Full TOTP authentication

### 4. **TOTP Splash Screen Redirect**
**Question**: Will unauthorized users be redirected to TOTP screen?

**Answer**: ✅ Already implemented
- HTTP proxy captures requests → captive portal redirect
- Code: `src/myproxy/proxy/http_proxy.py:112-156`

### 5. **Banned Content Splash Screen**
**Question**: Separate screen for blocked URLs/keywords vs authentication

**Answer**: ❌ Requires implementation
- New "Content Blocked" splash screen
- Distinct from TOTP authentication screen
- Different redirect logic for content vs auth blocking

### 6. **Script Exemption from Blocking**
**Question**: Ensure Pi's own scripts aren't blocked

**Answer**: ❌ Requires implementation
- Whitelist Pi's IP addresses in iptables
- Exempt SSH (22), admin web (8080), DNS, NTP
- Allow system updates and management traffic

---

## 6-PHASE ROLLOUT SYSTEM

### Phase Management Architecture
```
PhaseManager Class
├── Configuration: /etc/myproxy/phase.conf
├── Database: Phase-specific rules storage
├── Traffic Filter: Conditional rule application
└── Web Interface: Phase switching controls
```

### Detailed Phase Specifications

#### **Phase 1: Transparent Bridge**
- **Purpose**: Verify network connectivity works
- **Behavior**: Pass all traffic through without filtering
- **iptables**: ACCEPT all in FORWARD chain
- **Testing**: Confirm internet works, Pi accessible

#### **Phase 2: Traffic Monitoring Only**
- **Purpose**: Log and analyze household traffic patterns
- **Behavior**: Log all traffic but allow everything
- **Features**: Enhanced logging, traffic analysis dashboard
- **Testing**: Verify logging works, no blocking occurs

#### **Phase 3: Block NDTV.com Only**
- **Purpose**: Test specific domain blocking
- **Behavior**: Block NDTV.com (HTTP/HTTPS/DNS), allow everything else
- **Implementation**: Domain pattern matching in traffic filter
- **Testing**: Confirm NDTV blocked, other sites work

#### **Phase 4: Block Keywords ("mickey and jj")**
- **Purpose**: Test content inspection and keyword filtering
- **Behavior**: Block pages containing "mickey" or "jj", allow everything else
- **Implementation**: HTTP content inspection, keyword matching
- **Testing**: Confirm keyword blocking, performance impact assessment

#### **Phase 5: Google Sheets Integration**
- **Purpose**: Dynamic rule management
- **Behavior**: Read blocking rules from Google Sheets
- **Implementation**: Sheets API integration, periodic rule updates
- **Testing**: Add/remove rules via Sheets, verify real-time updates

#### **Phase 6: Full TOTP Authentication**
- **Purpose**: Complete security implementation
- **Behavior**: Block all traffic until TOTP authentication
- **Implementation**: Current system + all previous phases
- **Testing**: Full authentication workflow, session management

---

## REQUIRED NEW FEATURES

### 1. **Phase Management System**
```python
class PhaseManager:
    - load_phase_config()
    - apply_phase_rules()
    - switch_phase()
    - validate_phase_transition()
```

### 2. **Enhanced Traffic Filtering**
- **Keyword Filtering**: HTTP content inspection
- **URL Pattern Matching**: Regex-based domain blocking
- **Performance Optimization**: Efficient packet processing
- **Logging**: Detailed traffic analysis and reporting

### 3. **Google Sheets Integration**
```python
class SheetsRuleManager:
    - fetch_blocking_rules()
    - update_local_rules()
    - validate_rule_format()
    - periodic_sync()
```

### 4. **Pi Self-Exemption System**
- **IP Whitelisting**: Both 192.168.1.100 and 192.168.4.100
- **Service Exemption**: SSH, HTTP admin, DNS, NTP, system updates
- **iptables Rules**: ACCEPT before blocking rules

### 5. **Dual IP Networking Configuration**
- **Static IP Assignment**: WAN interface gets 192.168.1.100
- **Routing Priority**: eth0 metric 100, wlan0 metric 200
- **Conflict Prevention**: Proper routing table management
- **Backup Access**: WiFi remains on 192.168.4.100

### 6. **Enhanced Splash Screens**
- **TOTP Authentication**: Existing captive portal
- **Content Blocked**: New screen for banned URLs/keywords
- **Redirect Logic**: Different handling for auth vs content blocks

---

## IMPLEMENTATION STRATEGY

### BEFORE Moving Pi Inline (Weeks 1-2)
**Location**: Current safe environment (192.168.4.x network)

#### **Week 1: Core Development**
- ✅ Implement PhaseManager class and configuration system
- ✅ Build enhanced traffic filtering (keywords, URLs)
- ✅ Create Google Sheets integration
- ✅ Add Pi self-exemption iptables rules
- ✅ Develop new "Content Blocked" splash screen

#### **Week 2: Testing and Validation**
- ✅ Test all 6 phases in current environment
- ✅ Verify TOTP authentication still works
- ✅ Test keyword and URL blocking functionality
- ✅ Validate Google Sheets integration
- ✅ Confirm Pi exemption rules work
- ✅ Prepare static IP bridge configuration

### AFTER Moving Pi Inline (Week 3)
**Location**: Production inline deployment

#### **Day 1: Physical Installation**
- Connect hardware: ISP Router → Pi eth0 → Pi USB-eth → WiFi Router
- Configure static IP 192.168.1.100 on WAN interface
- Verify SSH access on both IPs (192.168.1.100 and 192.168.4.100)
- Start in Phase 1 (transparent bridge)

#### **Days 2-7: Gradual Rollout**
- **Day 2**: Phase 2 (monitoring only)
- **Day 3**: Phase 3 (block NDTV.com)
- **Day 4**: Phase 4 (block keywords)
- **Day 5**: Phase 5 (Google Sheets)
- **Day 6**: Phase 6 (full TOTP)
- **Day 7**: Monitor and optimize

---

## NETWORK CONFIGURATION PLAN

### Current Pi Status
```
WiFi (wlan0): 192.168.4.100 ✅
Ethernet (eth0): 192.168.4.65 ✅
Both on same subnet: 192.168.4.x/22
```

### Target Inline Configuration
```
WAN (eth0): 192.168.1.100 (static, primary)
WiFi (wlan0): 192.168.4.100 (backup access)
USB-Ethernet: No IP (bridge interface)
```

### Routing Configuration
```bash
# Primary internet route via eth0
ip route add default via 192.168.1.1 dev eth0 metric 100

# Backup route via wlan0  
ip route add default via 192.168.4.1 dev wlan0 metric 200

# Prevent routing conflicts
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
```

### Service Binding
- **SSH**: Listen on both 192.168.1.100:22 and 192.168.4.100:22
- **HTTP Admin**: Accessible on both 192.168.1.100:8080 and 192.168.4.100:8080
- **VNC**: Available on both IP addresses

---

## ARCHITECTURE OVERVIEW

### Network Architecture - Inline Mode (Future)
```
ISP Router (192.168.1.1) → Pi eth0 (192.168.1.100) → Pi USB-eth → WiFi Router WAN
                                    ↓
                          MyProxy Phase-Based Filtering
                             (FORWARD chain + phases)
                                    ↓
                        Phase 1: Transparent → Phase 6: Full TOTP
```

### Database Design (Enhanced)
- **Device Management**: MAC addresses, IP tracking, authentication sessions
- **Phase Configuration**: Current phase, phase-specific rules
- **Traffic Filtering**: Keyword rules, URL patterns, Google Sheets rules
- **Access Logging**: Authentication events, blocked content, phase transitions

---

## NEXT SESSION HANDOFF

### Context for Pi Claude Session
This document provides complete context for implementing the pre-inline development phase on the Raspberry Pi. The next Claude session should:

### **Priority Implementation Order**
1. **Phase Management System** (src/myproxy/phases/)
2. **Enhanced Traffic Filtering** (src/myproxy/network/enhanced_filter.py)
3. **Google Sheets Integration** (src/myproxy/integrations/sheets.py)
4. **Pi Self-Exemption Rules** (update traffic_monitor.py)
5. **Content Blocked Splash Screen** (src/myproxy/web/templates/)
6. **Dual IP Configuration** (scripts/configure-bridge-mode.sh)

### **Validation Requirements**
- Test each phase independently in current environment
- Verify no existing functionality breaks
- Confirm dual IP access works
- Test Google Sheets rule updates
- Validate content vs auth blocking logic

### **Testing Checklist**
- [ ] Phase 1: Network passes through transparently
- [ ] Phase 2: Traffic logging without blocking
- [ ] Phase 3: NDTV.com blocked, others allowed
- [ ] Phase 4: Keywords blocked, others allowed  
- [ ] Phase 5: Google Sheets rules applied dynamically
- [ ] Phase 6: Full TOTP + all previous features
- [ ] Pi self-exemption: SSH/admin always accessible
- [ ] Dual IP: Both 192.168.1.100 and 192.168.4.100 work

### **Files to Modify**
- `src/myproxy/phases/` (new directory)
- `src/myproxy/network/traffic_monitor.py`
- `src/myproxy/web/app.py`
- `scripts/configure-bridge-mode.sh`
- `docker-compose.pi.yml`

---

## TROUBLESHOOTING

### Common Commands
```bash
# Check current phase
cat /etc/myproxy/phase.conf

# Switch phases manually
echo "PHASE=1" | sudo tee -a /etc/myproxy/phase.conf

# Check service status
sudo systemctl status myproxy-dual

# View logs
sudo journalctl -u myproxy-dual -f

# Check interfaces and IPs
ip addr show

# Check iptables rules
sudo iptables -L -n -v

# Test dual IP access
ssh raspberrypi@192.168.1.100
ssh raspberrypi@192.168.4.100
```

### Phase Transition Issues
```bash
# Reset to Phase 1 (safe mode)
echo "PHASE=1" | sudo tee /etc/myproxy/phase.conf
sudo systemctl restart myproxy-dual

# Check phase-specific iptables
sudo iptables -L MYPROXY_FILTER -n -v

# Verify Pi self-exemption
sudo iptables -L | grep "192.168"
```

---

## DEVELOPMENT STATUS

**Current State**: ❌ Requires 2-3 weeks pre-inline development
**Next Step**: Implement phase management system on Pi
**Timeline**: 
- Week 1-2: Development and testing in safe environment
- Week 3: Inline deployment with gradual rollout
- Risk Level: Low (extensive pre-testing + gradual rollout)

**Key Success Factors**:
1. Complete all development before going inline
2. Test every phase thoroughly in current environment  
3. Maintain dual IP access for redundancy
4. Gradual rollout with easy rollback capability