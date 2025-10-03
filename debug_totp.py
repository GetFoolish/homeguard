#!/usr/bin/env python3
"""Debug TOTP codes to understand why validation is failing."""

import sys
sys.path.append('src')

from homeguard.auth.totp import totp_manager
from datetime import datetime

def debug_totp():
    """Debug current TOTP codes and validation."""
    print("🔐 TOTP Debug Information")
    print("=" * 50)

    # Get current valid codes
    current_codes = totp_manager.generate_current_codes()
    print("\n📋 Current Valid TOTP Codes:")
    for duration, code in current_codes.items():
        print(f"  {duration:15} | {code}")

    print(f"\n⏰ Current Time: {datetime.utcnow()}")
    print(f"🕐 Time until next code change: {totp_manager.get_time_remaining()} seconds")

    # Test codes that were failing
    failed_codes = [
        "795311",  # Without spaces
        "795 311", # With spaces
        "435832",
        "435 832",
        "084787",
        "084 787",
        "262300",
        "262 300",
        "102343",
        "102 343"
    ]

    print(f"\n🧪 Testing Failed Codes:")
    for code in failed_codes:
        result = totp_manager.validate_code(code)
        if result:
            duration, seconds = result
            print(f"  ✅ {code:10} | Valid for {duration} ({seconds}s)")
        else:
            print(f"  ❌ {code:10} | Invalid")

    # Show TOTP secrets for debugging
    secrets = totp_manager.get_generator_secrets()
    print(f"\n🔑 TOTP Secrets (for verification):")
    for duration, secret in secrets.items():
        print(f"  {duration:15} | {secret}")

    # Show provisioning URIs (these can be converted to QR codes)
    uris = totp_manager.get_provisioning_uris()
    print(f"\n🔗 Provisioning URIs (for QR codes):")
    for duration, uri in uris.items():
        print(f"  {duration:15} | {uri}")

if __name__ == "__main__":
    debug_totp()