#!/usr/bin/env python3
"""Quick script to get TOTP secrets and current codes for testing."""

import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from homeguard.auth.totp import totp_manager
import pyotp

def main():
    print("HomeguardGuard TOTP Information")
    print("=" * 40)
    
    # Get all secrets
    secrets = totp_manager.get_generator_secrets()
    
    for duration_key, secret in secrets.items():
        print(f"\nDuration: {duration_key}")
        print(f"Secret: {secret}")
        
        # Generate current TOTP code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        print(f"Current Code: {current_code}")
        
        # Show QR code URL for easy setup in authenticator apps
        qr_url = totp.provisioning_uri(
            name=f"HomeguardGuard-{duration_key}",
            issuer_name="HomeguardGuard Gateway"
        )
        print(f"QR Code URL: {qr_url}")
        print("-" * 40)

if __name__ == "__main__":
    main()