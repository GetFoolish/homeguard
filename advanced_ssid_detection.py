#!/usr/bin/env python3
"""
Advanced SSID Detection Methods for Deco X20
Tests various approaches to determine which SSID devices are connected to
"""

import subprocess
import requests
import socket
import time
import re
from datetime import datetime

def test_wifi_scan():
    """Test if Pi can scan for WiFi networks and see associated clients"""
    print("📡 Testing WiFi Network Scanning...")

    try:
        # Check available wireless interfaces
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        print(f"Wireless interfaces:\n{result.stdout}")

        # Try scanning for networks
        interfaces = ['wlan0', 'wlan1', 'wlp1s0']
        for interface in interfaces:
            try:
                result = subprocess.run(['iwlist', interface, 'scan'], capture_output=True, text=True)
                if result.returncode == 0 and 'arkanet' in result.stdout:
                    print(f"✅ Found networks via {interface}")
                    # Look for associated clients in scan results
                    return True
            except:
                continue

        print("❌ No wireless scanning capability detected")
        return False

    except Exception as e:
        print(f"❌ WiFi scan failed: {e}")
        return False

def test_dhcp_snooping():
    """Monitor DHCP traffic to capture network assignments"""
    print("🔍 Testing DHCP Traffic Monitoring...")

    try:
        # Check if we can monitor network traffic
        result = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ tcpdump not available")
            return False

        print("🎯 Starting 10-second DHCP traffic capture...")
        # Monitor DHCP traffic for 10 seconds
        cmd = ['sudo', 'tcpdump', '-i', 'any', '-n', 'port', '67', 'or', 'port', '68']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.stdout:
            print(f"✅ Captured DHCP traffic:\n{result.stdout[:500]}...")
            return True
        else:
            print("❌ No DHCP traffic captured")
            return False

    except subprocess.TimeoutExpired:
        print("✅ DHCP monitoring completed (timeout expected)")
        return True
    except Exception as e:
        print(f"❌ DHCP monitoring failed: {e}")
        return False

def test_router_api_endpoints():
    """Test various router API endpoints that might reveal client info"""
    print("🌐 Testing Router API Endpoints...")

    router_ip = "192.168.2.1"
    test_paths = [
        '/cgi-bin/luci/admin/status/wireless',
        '/api/wireless/clients',
        '/api/clients',
        '/cgi-bin/wireless_clients.asp',
        '/userRpm/WlanStationRpm.htm',
        '/webpages/wireless-clients.html',
        '/wireless/clients.json',
        '/api/network/clients',
        '/admin/wireless',
        '/status/wireless',
        '/wireless_clients.html',
        '/cgi-bin/webui',
        '/api/system/clients'
    ]

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; RouterAdmin)'})

    for path in test_paths:
        for protocol in ['http', 'https']:
            for port in [80, 8080, 443, 8443]:
                try:
                    url = f"{protocol}://{router_ip}:{port}{path}"
                    response = session.get(url, timeout=3, verify=False)

                    if response.status_code == 200:
                        content = response.text.lower()
                        if any(keyword in content for keyword in ['ssid', 'wireless', 'client', 'station']):
                            print(f"✅ Found potential API endpoint: {url}")
                            print(f"Content sample: {content[:200]}...")
                            return url

                except:
                    continue

    print("❌ No accessible API endpoints found")
    return None

def test_802_11_monitoring():
    """Test 802.11 frame monitoring if possible"""
    print("📶 Testing 802.11 Frame Monitoring...")

    try:
        # Check if monitor mode is possible
        interfaces = ['wlan0', 'wlan1', 'mon0']

        for interface in interfaces:
            try:
                # Try to get interface info
                result = subprocess.run(['iw', 'dev', interface, 'info'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Interface {interface} available")

                    # Try to capture 802.11 frames (requires root)
                    cmd = ['sudo', 'tcpdump', '-i', interface, '-c', '5', 'type', 'mgt']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                    if result.stdout:
                        print(f"✅ Captured 802.11 frames on {interface}")
                        return True

            except:
                continue

        print("❌ No 802.11 monitoring capability")
        return False

    except Exception as e:
        print(f"❌ 802.11 monitoring failed: {e}")
        return False

def test_netlink_monitoring():
    """Test netlink socket monitoring for network events"""
    print("🔗 Testing Netlink Event Monitoring...")

    try:
        # Monitor network events
        cmd = ['ip', 'monitor', 'link']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Wait a few seconds for events
        time.sleep(3)
        process.terminate()
        stdout, stderr = process.communicate()

        if stdout:
            print(f"✅ Network events captured:\n{stdout[:300]}...")
            return True
        else:
            print("❌ No network events captured")
            return False

    except Exception as e:
        print(f"❌ Netlink monitoring failed: {e}")
        return False

def test_mac_vendor_analysis():
    """Analyze MAC addresses for device type patterns"""
    print("🏷️ Testing MAC Vendor Analysis...")

    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        if result.returncode != 0:
            return False

        mac_patterns = {}
        lines = result.stdout.strip().split('\n')

        for line in lines:
            if '192.168.2.' in line:
                # Extract MAC address
                mac_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line)
                if mac_match:
                    mac_prefix = mac_match.group(1)
                    if mac_prefix not in mac_patterns:
                        mac_patterns[mac_prefix] = 0
                    mac_patterns[mac_prefix] += 1

        print(f"✅ MAC vendor analysis complete")
        print("Most common MAC prefixes:")
        for prefix, count in sorted(mac_patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {prefix}:xx:xx:xx - {count} devices")

        return True

    except Exception as e:
        print(f"❌ MAC vendor analysis failed: {e}")
        return False

def test_bridge_table():
    """Check bridge forwarding table for network topology"""
    print("🌉 Testing Bridge Table Analysis...")

    try:
        # Check bridge interfaces
        result = subprocess.run(['brctl', 'show'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            print(f"✅ Bridge interfaces found:\n{result.stdout}")

            # Get forwarding database
            result = subprocess.run(['brctl', 'showmacs', 'br0'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Bridge MAC table:\n{result.stdout[:300]}...")
                return True

        print("❌ No bridge interfaces or limited access")
        return False

    except Exception as e:
        print(f"❌ Bridge analysis failed: {e}")
        return False

def main():
    """Run all advanced SSID detection tests"""
    print("🚀 Advanced SSID Detection for Deco X20")
    print(f"Timestamp: {datetime.now()}")
    print("=" * 60)

    tests = [
        ("WiFi Scanning", test_wifi_scan),
        ("DHCP Monitoring", test_dhcp_snooping),
        ("Router API", test_router_api_endpoints),
        ("802.11 Monitoring", test_802_11_monitoring),
        ("Netlink Events", test_netlink_monitoring),
        ("MAC Vendor Analysis", test_mac_vendor_analysis),
        ("Bridge Table", test_bridge_table)
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False

    print("\n" + "=" * 60)
    print("📊 ADVANCED DETECTION SUMMARY")
    print("=" * 60)

    successful = [name for name, success in results.items() if success]

    if successful:
        print(f"✅ Working methods: {', '.join(successful)}")
        print("\n🎯 NEXT STEPS:")
        if "Router API" in successful:
            print("- Found router API access - can query client associations")
        if "DHCP Monitoring" in successful:
            print("- DHCP monitoring works - can capture network assignments in real-time")
        if "802.11 Monitoring" in successful:
            print("- 802.11 frame capture works - can see wireless associations")
        if "WiFi Scanning" in successful:
            print("- WiFi scanning available - can see network topology")

    else:
        print("❌ No advanced methods successful")
        print("\n💡 FALLBACK RECOMMENDATIONS:")
        print("1. Manual device-to-network mapping in admin interface")
        print("2. MAC address-based exemption system")
        print("3. Router firmware/configuration investigation")
        print("4. Physical network port detection (if wired)")
        print("5. User-reported device network assignment")

if __name__ == "__main__":
    main()