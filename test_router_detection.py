#!/usr/bin/env python3
"""
Test script to detect SSID/network information from Deco X20 router
Tests multiple methods: SNMP, web scraping, UPnP, and network analysis
"""

import subprocess
import requests
import socket
import json
from datetime import datetime

def log_result(method, success, data=None, error=None):
    """Log test results"""
    status = "✅ SUCCESS" if success else "❌ FAILED"
    print(f"\n{status} - {method}")
    if data:
        print(f"Data: {data}")
    if error:
        print(f"Error: {error}")
    print("-" * 50)

def test_snmp_discovery():
    """Test SNMP discovery on router"""
    print("🔍 Testing SNMP Discovery...")

    try:
        # Check if snmp tools are available
        result = subprocess.run(['which', 'snmpwalk'], capture_output=True, text=True)
        if result.returncode != 0:
            log_result("SNMP Tools Check", False, error="snmpwalk not installed")
            return False

        # Try common SNMP community strings
        communities = ['public', 'private', 'admin']
        router_ip = "192.168.2.1"

        for community in communities:
            try:
                # Test basic SNMP connectivity
                cmd = ['snmpwalk', '-v2c', '-c', community, router_ip, '1.3.6.1.2.1.1.1.0']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if result.returncode == 0 and result.stdout.strip():
                    log_result(f"SNMP Community '{community}'", True, result.stdout.strip())

                    # Try to get wireless client info
                    wireless_oids = [
                        '1.3.6.1.4.1.14988.1.1.1.2.1.1',  # MikroTik
                        '1.3.6.1.4.1.9.9.273.1.1.2.1.1',   # Cisco
                        '1.3.6.1.4.1.2021.13.15.1.1.2',   # Net-SNMP
                        '1.3.6.1.2.1.17.1.4.1.2'          # Bridge MIB
                    ]

                    for oid in wireless_oids:
                        cmd = ['snmpwalk', '-v2c', '-c', community, router_ip, oid]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if result.returncode == 0 and result.stdout.strip():
                            log_result(f"Wireless OID {oid}", True, result.stdout[:200] + "...")
                            return True

                    return True

            except subprocess.TimeoutExpired:
                log_result(f"SNMP Community '{community}'", False, error="Timeout")
            except Exception as e:
                log_result(f"SNMP Community '{community}'", False, error=str(e))

        return False

    except Exception as e:
        log_result("SNMP Discovery", False, error=str(e))
        return False

def test_web_interface():
    """Test web interface access to router"""
    print("🌐 Testing Web Interface Access...")

    router_ip = "192.168.2.1"
    common_ports = [80, 8080, 443, 8443]

    for port in common_ports:
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{router_ip}:{port}"
                response = requests.get(url, timeout=3, verify=False)

                if response.status_code == 200:
                    log_result(f"Web Interface {url}", True,
                             f"Status: {response.status_code}, Content-Length: {len(response.text)}")

                    # Look for Deco-specific patterns
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['deco', 'tp-link', 'wifi', 'wireless']):
                        print(f"🎯 Found router-specific content at {url}")
                        return url

            except requests.exceptions.RequestException as e:
                continue

    log_result("Web Interface", False, error="No accessible web interface found")
    return None

def test_upnp_discovery():
    """Test UPnP device discovery"""
    print("📡 Testing UPnP Discovery...")

    try:
        # UPnP SSDP discovery
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "ST: upnp:rootdevice\r\n"
            "MX: 3\r\n\r\n"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))

        devices = []
        try:
            while True:
                data, addr = sock.recvfrom(1024)
                if addr[0] == "192.168.2.1":  # Router IP
                    devices.append(data.decode())
        except socket.timeout:
            pass

        sock.close()

        if devices:
            log_result("UPnP Discovery", True, f"Found {len(devices)} responses from router")
            for i, device in enumerate(devices):
                print(f"Device {i+1}:\n{device}\n")
            return True
        else:
            log_result("UPnP Discovery", False, error="No UPnP responses from router")
            return False

    except Exception as e:
        log_result("UPnP Discovery", False, error=str(e))
        return False

def test_arp_analysis():
    """Analyze ARP table for network patterns"""
    print("🔍 Testing ARP Table Analysis...")

    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        if result.returncode != 0:
            log_result("ARP Analysis", False, error="Failed to read ARP table")
            return False

        lines = result.stdout.strip().split('\n')
        devices = []

        for line in lines:
            if '192.168.2.' in line:
                parts = line.split()
                if len(parts) >= 4:
                    hostname = parts[0] if parts[0] != '?' else 'Unknown'
                    ip = parts[1].strip('()')
                    mac = parts[3] if len(parts) > 3 else 'Unknown'
                    devices.append({'hostname': hostname, 'ip': ip, 'mac': mac})

        # Analyze IP patterns
        ip_ranges = {}
        for device in devices:
            ip_parts = device['ip'].split('.')
            if len(ip_parts) == 4:
                last_octet = int(ip_parts[3])
                range_key = f"{ip_parts[2]}.{last_octet//50*50}-{ip_parts[2]}.{(last_octet//50+1)*50-1}"
                if range_key not in ip_ranges:
                    ip_ranges[range_key] = []
                ip_ranges[range_key].append(device)

        log_result("ARP Analysis", True, f"Found {len(devices)} devices in {len(ip_ranges)} IP ranges")

        for range_key, range_devices in ip_ranges.items():
            print(f"\nIP Range {range_key}: {len(range_devices)} devices")
            for device in range_devices[:3]:  # Show first 3
                print(f"  {device['ip']} - {device['hostname']} ({device['mac'][:8]}...)")

        return devices

    except Exception as e:
        log_result("ARP Analysis", False, error=str(e))
        return None

def test_dhcp_leases():
    """Check for DHCP lease information"""
    print("📋 Testing DHCP Lease Analysis...")

    lease_files = [
        '/var/lib/dhcp/dhcpd.leases',
        '/var/lib/dhcpcd5/dhcpcd.leases',
        '/tmp/dhcp.leases',
        '/var/lib/NetworkManager/dhcpcd.leases'
    ]

    for lease_file in lease_files:
        try:
            with open(lease_file, 'r') as f:
                content = f.read()
                log_result(f"DHCP Leases {lease_file}", True, f"File size: {len(content)} bytes")

                # Look for network identifier patterns
                if 'option domain-name' in content or 'ssid' in content.lower():
                    print("🎯 Found potential network identifiers in DHCP leases")

                return True

        except FileNotFoundError:
            continue
        except Exception as e:
            log_result(f"DHCP Leases {lease_file}", False, error=str(e))

    log_result("DHCP Leases", False, error="No accessible DHCP lease files found")
    return False

def main():
    """Run all router detection tests"""
    print("🚀 Starting Router Detection Tests for Deco X20")
    print(f"Timestamp: {datetime.now()}")
    print("=" * 60)

    results = {
        'snmp': test_snmp_discovery(),
        'web': test_web_interface(),
        'upnp': test_upnp_discovery(),
        'arp': test_arp_analysis(),
        'dhcp': test_dhcp_leases()
    }

    print("\n" + "=" * 60)
    print("📊 SUMMARY OF RESULTS")
    print("=" * 60)

    successful_methods = [method for method, success in results.items() if success]

    if successful_methods:
        print(f"✅ Working methods: {', '.join(successful_methods)}")
        print("\n🎯 RECOMMENDATIONS:")

        if 'snmp' in successful_methods:
            print("- SNMP access available - can query wireless client tables")
        if 'web' in successful_methods:
            print("- Web interface accessible - can scrape device/network info")
        if 'upnp' in successful_methods:
            print("- UPnP available - can discover device capabilities")
        if 'arp' in successful_methods:
            print("- ARP analysis shows network patterns - can infer SSID by IP ranges")
        if 'dhcp' in successful_methods:
            print("- DHCP leases available - may contain network identifiers")

    else:
        print("❌ No methods successful - will need alternative approach")
        print("\n💡 ALTERNATIVE SUGGESTIONS:")
        print("- Manual IP range configuration per SSID")
        print("- Device-specific exemption by MAC address")
        print("- Router firmware upgrade for better API access")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()