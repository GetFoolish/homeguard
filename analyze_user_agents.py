#!/usr/bin/env python3
"""
Analyze User-Agent patterns to identify IoT devices
"""

import re
import subprocess
from collections import defaultdict

def get_current_user_agents():
    """Extract User-Agents from current HomeguardGuard logs"""
    try:
        # Get recent logs
        result = subprocess.run([
            'sudo', 'journalctl', '-u', 'homeguard.service',
            '--since', '2 hours ago', '--no-pager'
        ], capture_output=True, text=True)

        user_agents = []
        for line in result.stdout.split('\n'):
            if 'User-Agent' in line:
                user_agents.append(line)

        return user_agents
    except Exception as e:
        print(f"Error getting logs: {e}")
        return []

def analyze_iot_patterns():
    """Known IoT device User-Agent patterns"""

    iot_patterns = {
        # Smart TVs
        'smart_tv': [
            r'.*SmartTV.*',
            r'.*SMART-TV.*',
            r'.*WebOS.*',
            r'.*Tizen.*',
            r'.*roku.*',
            r'.*AndroidTV.*',
            r'.*AppleTV.*',
            r'.*LG Browser.*',
            r'.*Samsung.*TV.*'
        ],

        # Gaming Consoles
        'gaming': [
            r'.*PlayStation.*',
            r'.*Xbox.*',
            r'.*Nintendo.*',
            r'.*Steam.*'
        ],

        # Smart Home Devices
        'smart_home': [
            r'.*Alexa.*',
            r'.*GoogleHome.*',
            r'.*Nest.*',
            r'.*Ring.*',
            r'.*Philips.*Hue.*',
            r'.*IoT.*',
            r'.*SmartDevice.*'
        ],

        # Security Cameras
        'cameras': [
            r'.*Camera.*',
            r'.*IPCam.*',
            r'.*AXIS.*',
            r'.*Hikvision.*',
            r'.*Dahua.*',
            r'.*ONVIF.*'
        ],

        # Connectivity Checks (often IoT)
        'connectivity_check': [
            r'.*CaptiveNetworkSupport.*',
            r'.*ConnectivityCheck.*',
            r'.*NetworkProbe.*',
            r'.*WifiProbe.*'
        ],

        # Embedded/Minimal browsers
        'embedded': [
            r'.*ESP32.*',
            r'.*ESP8266.*',
            r'.*Arduino.*',
            r'.*lwIP.*',
            r'.*Embedded.*',
            r'.*curl.*',
            r'.*wget.*'
        ],

        # Mobile without full browsers (often IoT apps)
        'minimal_mobile': [
            r'.*CFNetwork.*',  # iOS background requests
            r'.*okhttp.*',     # Android HTTP library
            r'.*Dalvik.*'      # Android runtime
        ]
    }

    return iot_patterns

def test_against_patterns(test_agents):
    """Test User-Agents against IoT patterns"""

    patterns = analyze_iot_patterns()
    results = defaultdict(list)

    for agent in test_agents:
        agent_lower = agent.lower()
        categorized = False

        for category, category_patterns in patterns.items():
            for pattern in category_patterns:
                if re.search(pattern.lower(), agent_lower):
                    results[category].append(agent)
                    categorized = True
                    break
            if categorized:
                break

        if not categorized:
            results['unknown'].append(agent)

    return results

def simulate_common_iot_agents():
    """Simulate common IoT device User-Agents for testing"""

    common_iot_agents = [
        # Real IoT User-Agents I've seen
        "Mozilla/5.0 (SMART-TV; Linux; Tizen 5.5) AppleWebKit/538.1",
        "Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36 WebAppManager",
        "Roku/DVP-9.10 (519.10E04111A)",
        "AppleTV11,1/13.4.8",
        "PlayStation 5/3.21 (PlayStation 5)",
        "Xbox/2108.1000.21.0",
        "CaptiveNetworkSupport-355.200.27 wispr",
        "WiFiProbe/1.0",
        "ConnectivityCheck/1.0",
        "ESP32HTTPClient",
        "curl/7.68.0",
        "okhttp/4.9.0",
        "CFNetwork/1206 Darwin/20.1.0",
        "Dalvik/2.1.0 (Linux; U; Android 10; SM-G973F Build/QP1A.190711.020)",
        "Ring/1.0 (com.ring.doorbell; build:1; iOS 14.4.0) Alamofire/5.2.2",
        "Nest/5.49.0.15 CFNetwork/1206 Darwin/20.1.0",
        "Philips Hue/1.0",
        "AXIS-Linux/9.80.1 UPnP/1.0 AXIS_Video_Server/9.80.1",
        "Hikvision-Webs/V4.0",
        "Python-urllib/3.8",  # Often used by IoT devices
        "Java/1.8.0_271"      # Often used by IoT devices
    ]

    return common_iot_agents

def main():
    print("🔍 IoT Device User-Agent Analysis")
    print("=" * 50)

    # Get current User-Agents from logs
    print("📋 Checking current HomeguardGuard logs...")
    current_agents = get_current_user_agents()
    print(f"Found {len(current_agents)} User-Agent entries in logs")

    # Test with simulated IoT agents
    print("\n🧪 Testing with known IoT User-Agent patterns...")
    test_agents = simulate_common_iot_agents()

    results = test_against_patterns(test_agents)

    print("\n📊 IoT Device Classification Results:")
    print("=" * 50)

    for category, agents in results.items():
        if agents and category != 'unknown':
            print(f"\n🏷️ {category.upper().replace('_', ' ')} ({len(agents)} devices):")
            for agent in agents[:3]:  # Show first 3
                print(f"  • {agent[:80]}...")

    if results['unknown']:
        print(f"\n❓ UNKNOWN ({len(results['unknown'])} devices):")
        for agent in results['unknown'][:3]:
            print(f"  • {agent[:80]}...")

    # Show pattern matching logic
    print("\n🎯 RECOMMENDED IoT AUTO-DETECTION RULES:")
    print("=" * 50)

    detected_categories = [cat for cat in results.keys() if cat != 'unknown' and results[cat]]

    if detected_categories:
        print("✅ Auto-exempt these device types:")
        for category in detected_categories:
            print(f"  - {category.replace('_', ' ').title()}")

        print(f"\n📝 Implementation: Add User-Agent pattern matching to device detection")
        print(f"   When device makes HTTP request, check User-Agent against IoT patterns")
        print(f"   If match found, automatically suggest/apply TOTP exemption")
    else:
        print("❌ No clear IoT patterns detected")
        print("💡 Recommendation: Use manual device classification")

    print(f"\n🚀 NEXT STEPS:")
    print(f"1. Monitor actual User-Agents from your network")
    print(f"2. Implement pattern matching in device discovery")
    print(f"3. Create admin interface for device classification")
    print(f"4. Add automatic exemption suggestions")

if __name__ == "__main__":
    main()