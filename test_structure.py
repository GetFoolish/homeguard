#!/usr/bin/env python3
"""Test script to validate Homeguard v4 structure."""

import os
import sys
from pathlib import Path

def test_file_structure():
    """Test that all required files exist."""
    required_files = [
        "src/main.py",
        "src/homeguard/__init__.py",
        "src/homeguard/config/__init__.py",
        "src/homeguard/config/settings.py",
        "src/homeguard/database/__init__.py",
        "src/homeguard/database/models.py",
        "src/homeguard/database/connection.py",
        "src/homeguard/auth/__init__.py",
        "src/homeguard/auth/totp.py",
        "src/homeguard/iptables/__init__.py",
        "src/homeguard/iptables/manager.py",
        "src/homeguard/api/__init__.py",
        "src/homeguard/api/service.py",
        "src/homeguard/network/__init__.py",
        "src/homeguard/network/scanner.py",
        "src/homeguard/frontend/__init__.py",
        "src/homeguard/frontend/templates/dashboard.html",
        "requirements.txt",
        "README.md",
        "totp_secrets.json"
    ]

    print("Testing file structure...")
    missing_files = []

    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"  ❌ Missing: {file_path}")
        else:
            print(f"  ✅ Found: {file_path}")

    if missing_files:
        print(f"\n❌ {len(missing_files)} files missing!")
        return False
    else:
        print(f"\n✅ All {len(required_files)} required files present!")
        return True


def test_key_functions():
    """Test that key functions are defined in the code."""
    print("\nTesting key functions...")

    checks = [
        ("src/homeguard/api/service.py", "set_mode_to_transparent"),
        ("src/homeguard/api/service.py", "set_mode_to_totp"),
        ("src/homeguard/api/service.py", "validate_totp"),
        ("src/homeguard/api/service.py", "grant_access_to_ip"),
        ("src/homeguard/api/service.py", "block_access_to_ip"),
        ("src/homeguard/api/service.py", "grant_access_to_iot"),
        ("src/homeguard/api/service.py", "check_expired_devices"),
        ("src/homeguard/iptables/manager.py", "set_transparent_mode"),
        ("src/homeguard/iptables/manager.py", "set_totp_mode"),
        ("src/homeguard/database/models.py", "class Device"),
    ]

    all_found = True
    for file_path, function_name in checks:
        with open(file_path, 'r') as f:
            content = f.read()
            if function_name in content:
                print(f"  ✅ Found '{function_name}' in {file_path}")
            else:
                print(f"  ❌ Missing '{function_name}' in {file_path}")
                all_found = False

    return all_found


def test_testing_mode():
    """Verify system is in TESTING mode."""
    print("\nTesting TESTING mode configuration...")

    with open("src/homeguard/config/settings.py", 'r') as f:
        content = f.read()
        if 'default="testing"' in content:
            print("  ✅ Execution mode defaults to TESTING")
            return True
        else:
            print("  ❌ Execution mode not set to TESTING by default")
            return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("🧪 HOMEGUARD V4.0 STRUCTURE TEST")
    print("=" * 60)

    results = []

    results.append(test_file_structure())
    results.append(test_key_functions())
    results.append(test_testing_mode())

    print("\n" + "=" * 60)
    if all(results):
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Install dependencies: pip3 install -r requirements.txt")
        print("2. Start the service: python3 src/main.py")
        print("3. Access dashboard: http://192.168.2.1:8081/")
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
