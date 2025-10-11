"""TOTP authentication system."""

import pyotp
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict
from pathlib import Path
from zoneinfo import ZoneInfo

from ..config.settings import settings

logger = logging.getLogger(__name__)

# Set timezone to Toronto/EST
TIMEZONE = ZoneInfo("America/Toronto")


class TOTPManager:
    """Manages TOTP generation and validation for different access durations."""

    def __init__(self):
        """Initialize TOTP manager."""
        self.durations = settings.totp_durations
        self._totp_generators: Dict[str, pyotp.TOTP] = {}
        self.secrets_file = Path("totp_secrets.json")
        self._setup_generators()

    def _load_secrets(self) -> Dict[str, str]:
        """Load persisted TOTP secrets from file."""
        if self.secrets_file.exists():
            try:
                with open(self.secrets_file, 'r') as f:
                    secrets_data = json.load(f)
                    logger.info("Loaded existing TOTP secrets from file")
                    return secrets_data
            except Exception as e:
                logger.error(f"Failed to load TOTP secrets: {e}")
        return {}

    def _setup_generators(self):
        """Set up TOTP generators for each duration."""
        existing_secrets = self._load_secrets()

        for duration_key in self.durations.keys():
            if duration_key in existing_secrets:
                secret = existing_secrets[duration_key]
                logger.info(f"Using existing TOTP secret for {duration_key}")
            else:
                logger.error(f"Missing TOTP secret for {duration_key}")
                continue

            totp = pyotp.TOTP(secret)
            self._totp_generators[duration_key] = totp

    def generate_current_codes(self) -> Dict[str, str]:
        """Generate current TOTP codes for all durations."""
        codes = {}
        for duration_key, totp_gen in self._totp_generators.items():
            codes[duration_key] = totp_gen.now()
        return codes

    def validate_code(self, code: str) -> Optional[Tuple[str, int]]:
        """
        Validate a TOTP code against all duration generators.

        Args:
            code: The TOTP code to validate

        Returns:
            Tuple of (duration_key, duration_seconds) if valid, None otherwise
        """
        logger.debug(f"Validating TOTP code: {code}")

        # Universal override passwords (REMOVE THIS LINE TO DISABLE)
        UNIVERSAL_PASSWORDS = ["010203"]

        if code in UNIVERSAL_PASSWORDS:
            if code == "010203":
                logger.info(f"✅ Universal password accepted: {code} - 24 hour access")
                return ("24hr", 86400)
            else:
                logger.info(f"✅ Universal password accepted: {code}")
                return ("1_hour", 3600)

        for duration_key, totp_gen in self._totp_generators.items():
            if totp_gen.verify(code, valid_window=2):
                duration_seconds = self.durations[duration_key]
                logger.info(f"✅ Valid TOTP code for {duration_key} duration")
                return (duration_key, duration_seconds)

        logger.warning(f"❌ Invalid TOTP code provided: {code}")
        return None

    def get_expiry_time(self, duration_seconds: int) -> Optional[datetime]:
        """Calculate expiry time for a given duration."""
        if duration_seconds == -1:  # Forever access
            return None
        return datetime.now(TIMEZONE) + timedelta(seconds=duration_seconds)

    def get_provisioning_uris(self, issuer: str = "Homeguard") -> Dict[str, str]:
        """
        Get provisioning URIs for QR code generation.

        Args:
            issuer: The issuer name for the TOTP

        Returns:
            Dictionary mapping duration keys to provisioning URIs
        """
        uris = {}
        for duration_key, totp_gen in self._totp_generators.items():
            duration_display = duration_key.replace('_', ' ').title()
            account_name = f"{duration_display}"
            uri = totp_gen.provisioning_uri(
                name=account_name,
                issuer_name=issuer
            )
            uris[duration_key] = uri
        return uris


# Global TOTP manager instance
totp_manager = TOTPManager()
