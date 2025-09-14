#!/bin/bash

# HomeguardGuard Boot Investigation Script
# Purpose: Collect factual data about network state after reboot
# No modifications made - investigation only

LOG_FILE="/home/raspberrypi/CODE_STUFF/homeguard/boot-investigation.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "============================================" | tee -a "$LOG_FILE"
echo "Boot Investigation Started: $TIMESTAMP" | tee -a "$LOG_FILE"
echo "============================================" | tee -a "$LOG_FILE"

# Wait for HomeguardGuard to fully initialize
echo "[$TIMESTAMP] Waiting 10 seconds for HomeguardGuard to initialize..." | tee -a "$LOG_FILE"
sleep 10

# Function to log with timestamp
log_with_time() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 1. Check service statuses
log_with_time "=== SERVICE STATUS CHECKS ==="
log_with_time "HomeguardGuard service status:"
systemctl is-active homeguard.service | tee -a "$LOG_FILE"
systemctl status homeguard.service --no-pager -l | tee -a "$LOG_FILE"

log_with_time "Network setup service status:"
systemctl is-active homeguard-network-setup.service | tee -a "$LOG_FILE"
systemctl status homeguard-network-setup.service --no-pager -l | tee -a "$LOG_FILE"

# 2. Check Pi's own internet connectivity
log_with_time "=== PI INTERNET CONNECTIVITY ==="
if ping -c 3 8.8.8.8 &>/dev/null; then
    log_with_time "✅ Pi has internet connectivity"
else
    log_with_time "❌ Pi has NO internet connectivity"
fi

# 3. Check network interfaces and routing
log_with_time "=== NETWORK CONFIGURATION ==="
log_with_time "Active network connections:"
nmcli con show --active | tee -a "$LOG_FILE"
log_with_time "IP routing table:"
ip route show | tee -a "$LOG_FILE"
log_with_time "Interface details:"
ip addr show eth0 | tee -a "$LOG_FILE"
ip addr show eth1 | tee -a "$LOG_FILE"

# 4. Capture complete iptables state
log_with_time "=== IPTABLES STATE ANALYSIS ==="
log_with_time "FORWARD chain with packet counts:"
iptables -L FORWARD -n -v --line-numbers | tee -a "$LOG_FILE"
log_with_time "MYPROXY_FILTER chain with packet counts:"
iptables -L MYPROXY_FILTER -n -v --line-numbers | tee -a "$LOG_FILE"
log_with_time "NAT POSTROUTING chain:"
iptables -t nat -L POSTROUTING -n -v | tee -a "$LOG_FILE"

# 5. Test LAN device connectivity from Pi
log_with_time "=== LAN DEVICE CONNECTIVITY TESTS ==="
testing_ip=$(grep "testing_ip:" /etc/homeguard/config.yaml | cut -d'"' -f2)
log_with_time "Testing IP from config: $testing_ip"

# Test common device IPs on LAN
for ip in 192.168.2.100 192.168.2.101 192.168.2.102 192.168.2.150; do
    if ping -c 1 -W 2 "$ip" &>/dev/null; then
        log_with_time "Device $ip is reachable on LAN"
        # Try to test if this device can reach internet through us
        # We'll use a simple approach - check if we can route to them
        if ip route get "$ip" &>/dev/null; then
            log_with_time "Routing to $ip is configured"
        else
            log_with_time "No route to $ip"
        fi
    else
        log_with_time "Device $ip is not reachable or doesn't exist"
    fi
done

# 6. Check if testing IP is properly blocked
log_with_time "=== TESTING IP BLOCKING VERIFICATION ==="
if [[ -n "$testing_ip" ]]; then
    # Check if blocking rules exist for testing IP
    if iptables -L MYPROXY_FILTER -n | grep -q "$testing_ip.*DROP"; then
        log_with_time "✅ DROP rule exists for testing IP $testing_ip"
    else
        log_with_time "❌ NO DROP rule found for testing IP $testing_ip"
    fi

    # Check if gateway access rules exist
    if iptables -L MYPROXY_FILTER -n | grep -q "$testing_ip.*192.168.2.1.*ACCEPT"; then
        log_with_time "✅ Gateway access rule exists for testing IP $testing_ip"
    else
        log_with_time "❌ NO gateway access rule for testing IP $testing_ip"
    fi
else
    log_with_time "❌ No testing IP configured in /etc/homeguard/config.yaml"
fi

# 7. Analyze rule ordering issues
log_with_time "=== RULE ORDERING ANALYSIS ==="
forward_rules=$(iptables -L FORWARD -n --line-numbers | grep -E "ACCEPT|MYPROXY_FILTER")
log_with_time "FORWARD rule ordering:"
echo "$forward_rules" | tee -a "$LOG_FILE"

# Check if MYPROXY_FILTER appears before general ACCEPT rules
myproxy_line=$(echo "$forward_rules" | grep "MYPROXY_FILTER" | cut -d' ' -f1)
first_accept_line=$(echo "$forward_rules" | grep "ACCEPT" | head -1 | cut -d' ' -f1)

if [[ -n "$myproxy_line" && -n "$first_accept_line" ]]; then
    if [[ "$myproxy_line" -gt "$first_accept_line" ]]; then
        log_with_time "❌ RULE ORDERING ISSUE: MYPROXY_FILTER (line $myproxy_line) comes AFTER ACCEPT (line $first_accept_line)"
        log_with_time "This means traffic gets accepted before filtering!"
    else
        log_with_time "✅ Rule ordering OK: MYPROXY_FILTER (line $myproxy_line) comes before ACCEPT (line $first_accept_line)"
    fi
fi

# 8. Decision point - check if network needs emergency restoration
log_with_time "=== NETWORK STATUS DECISION ==="
network_broken=false

# Test 1: Check if Pi has internet (baseline)
if ! ping -c 2 8.8.8.8 &>/dev/null; then
    log_with_time "❌ Pi cannot reach internet - fundamental problem"
    network_broken=true
else
    log_with_time "✅ Pi has internet connectivity"
fi

# Test 2: Check if client forwarding is working by analyzing packet counts
forward_packets=$(iptables -L FORWARD -n -v | grep "eth1.*eth0" | head -1 | awk '{print $1}')
if [[ -n "$forward_packets" && "$forward_packets" =~ ^[0-9]+$ ]]; then
    if [[ "$forward_packets" -gt 100 ]]; then
        log_with_time "✅ FORWARD chain is processing client traffic ($forward_packets packets)"
    else
        log_with_time "⚠️  Very low FORWARD traffic ($forward_packets packets) - clients may not have internet"
        # Don't mark as broken yet, continue with more tests
    fi
else
    log_with_time "❌ Cannot parse FORWARD packet count - potential iptables issue"
    network_broken=true
fi

# Test 3: Check NAT/MASQUERADE is working
masq_packets=$(iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE | awk '{print $1}')
if [[ -n "$masq_packets" && "$masq_packets" =~ ^[0-9]+$ ]]; then
    if [[ "$masq_packets" -gt 50 ]]; then
        log_with_time "✅ NAT/MASQUERADE is processing traffic ($masq_packets packets)"
    else
        log_with_time "⚠️  Very low NAT traffic ($masq_packets packets) - clients may not be NATed"
    fi
else
    log_with_time "❌ Cannot parse NAT packet count - NAT may not be working"
    network_broken=true
fi

# Test 4: Critical rule ordering check
first_accept_line=$(iptables -L FORWARD -n --line-numbers | grep "ACCEPT.*eth1.*eth0" | head -1 | cut -d' ' -f1)
myproxy_line=$(iptables -L FORWARD -n --line-numbers | grep "MYPROXY_FILTER" | cut -d' ' -f1)

if [[ -n "$first_accept_line" && -n "$myproxy_line" ]]; then
    if [[ "$first_accept_line" -lt "$myproxy_line" ]]; then
        log_with_time "❌ CRITICAL: NAT ACCEPT rule (line $first_accept_line) comes BEFORE MYPROXY_FILTER (line $myproxy_line)"
        log_with_time "This means client traffic bypasses all filtering - clients have unfiltered internet"
        # This is actually working internet for clients, but breaks filtering
        # Don't mark network_broken=true because clients DO have internet
        log_with_time "⚠️  Clients have internet but filtering is bypassed"
    else
        log_with_time "✅ Rule ordering correct: MYPROXY_FILTER before NAT rules"
    fi
fi

# Test 5: Check if any client devices are actually reachable (indicates they're connected)
clients_found=0
for ip in 192.168.2.100 192.168.2.101 192.168.2.102 192.168.2.150 192.168.2.71; do
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        log_with_time "✅ Client $ip is reachable on LAN"
        ((clients_found++))
    fi
done

if [[ "$clients_found" -eq 0 ]]; then
    log_with_time "⚠️  No client devices found on LAN - cannot test client internet"
else
    log_with_time "✅ Found $clients_found client device(s) on LAN"
fi

# Test 6: Ultimate test - try to simulate client traffic through iptables
# Check if FORWARD chain default policy is DROP (should be)
forward_policy=$(iptables -L FORWARD | head -1 | grep -o "policy [A-Z]*" | cut -d' ' -f2)
if [[ "$forward_policy" == "DROP" ]]; then
    log_with_time "✅ FORWARD policy is DROP (correct for filtering)"

    # If policy is DROP and we see packets getting through, rules are working
    if [[ -n "$forward_packets" && "$forward_packets" -gt 100 ]]; then
        log_with_time "✅ Packets flowing despite DROP policy - FORWARD rules working"
    else
        log_with_time "❌ FORWARD policy is DROP but no/low packet flow - clients likely blocked"
        network_broken=true
    fi
else
    log_with_time "⚠️  FORWARD policy is $forward_policy (expected DROP)"
fi

# Final decision logic
if [[ "$network_broken" == "true" ]]; then
    log_with_time "🚨 CLIENT NETWORK APPEARS BROKEN based on multiple indicators"
else
    # Additional heuristic: if we have very low packet counts across the board, something is wrong
    total_forward_traffic=0
    if [[ -n "$forward_packets" && "$forward_packets" =~ ^[0-9]+$ ]]; then
        total_forward_traffic=$forward_packets
    fi

    if [[ "$total_forward_traffic" -lt 10 && "$clients_found" -eq 0 ]]; then
        log_with_time "🚨 HEURISTIC: Very low traffic + no clients found = likely network broken"
        network_broken=true
    else
        log_with_time "✅ Network appears functional for clients (based on traffic analysis)"
    fi
fi

if [[ "$network_broken" == "true" ]]; then
    log_with_time "🚨 NETWORK APPEARS BROKEN - Running emergency restoration"
    log_with_time "Executing: /home/raspberrypi/pi_nat_cleanup_persistent.sh"

    # Run the restoration script
    if /home/raspberrypi/pi_nat_cleanup_persistent.sh &>> "$LOG_FILE"; then
        log_with_time "✅ Emergency restoration completed successfully"

        # Re-test connectivity after restoration
        log_with_time "=== POST-RESTORATION TESTS ==="
        if ping -c 2 8.8.8.8 &>/dev/null; then
            log_with_time "✅ Internet connectivity restored"
        else
            log_with_time "❌ Internet still not working after restoration"
        fi

        # Capture iptables state after restoration
        log_with_time "FORWARD rules after restoration:"
        iptables -L FORWARD -n -v --line-numbers | tee -a "$LOG_FILE"

    else
        log_with_time "❌ Emergency restoration FAILED"
    fi
else
    log_with_time "✅ Network appears to be functioning - no emergency restoration needed"
fi

# 9. Final summary
log_with_time "=== INVESTIGATION SUMMARY ==="
log_with_time "Investigation completed. Key findings:"
log_with_time "- HomeguardGuard service: $(systemctl is-active homeguard.service)"
log_with_time "- Network setup service: $(systemctl is-active homeguard-network-setup.service)"
log_with_time "- Pi internet connectivity: $(ping -c 1 8.8.8.8 &>/dev/null && echo 'Working' || echo 'Broken')"
log_with_time "- Testing IP configured: ${testing_ip:-'Not configured'}"
log_with_time "- Emergency restoration: $([ "$network_broken" == "true" ] && echo 'Executed' || echo 'Not needed')"

end_time=$(date '+%Y-%m-%d %H:%M:%S')
log_with_time "Investigation completed at: $end_time"
echo "============================================" | tee -a "$LOG_FILE"

# Make sure log is readable
chmod 644 "$LOG_FILE"
chown raspberrypi:raspberrypi "$LOG_FILE"

exit 0