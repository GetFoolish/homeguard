#!/usr/bin/env python3
"""Generate QR codes for TOTP setup."""

import sys
sys.path.append('src')

import qrcode
from homeguard.auth.totp import totp_manager
import os

def generate_qr_codes():
    """Generate QR codes for all TOTP durations."""
    print("🔐 Generating TOTP QR Codes")
    print("=" * 50)

    # Create qr_codes directory if it doesn't exist
    os.makedirs("qr_codes", exist_ok=True)

    # Get provisioning URIs
    uris = totp_manager.get_provisioning_uris()

    print("\n📱 QR Codes generated for TOTP setup:")
    print("Scan these with your authenticator app (Google Authenticator, Authy, etc.)\n")

    for duration, uri in uris.items():
        try:
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)

            # Create QR code image
            img = qr.make_image(fill_color="black", back_color="white")
            filename = f"qr_codes/{duration}_totp_qr.png"
            img.save(filename)

            print(f"✅ {duration:15} | {filename}")
            print(f"   URI: {uri}")
            print()

        except Exception as e:
            print(f"❌ Failed to generate QR for {duration}: {e}")

    print(f"\n📂 QR codes saved in: ./qr_codes/")
    print("📱 Scan any QR code with your authenticator app to add it")
    print("🔢 Each QR code corresponds to a different access duration")

if __name__ == "__main__":
    generate_qr_codes()