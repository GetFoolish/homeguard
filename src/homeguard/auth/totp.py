"""TOTP authentication system with multiple duration support."""

import pyotp
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from enum import Enum
import logging
import json
import os
from pathlib import Path

from ..config.settings import settings

logger = logging.getLogger(__name__)


class AccessDuration(Enum):
    """Available access duration types."""
    FIFTEEN_MIN = "15min"
    THIRTY_MIN = "30min"
    ONE_HOUR = "1hr"
    TWO_HOUR = "2hr"
    FOUR_HOUR = "4hr"
    TWENTY_FOUR_HOUR = "24hr"
    ONE_WEEK = "1week"
    FOREVER = "forever"


class TOTPManager:
    """Manages TOTP generation and validation for different access durations."""
    
    def __init__(self):
        """Initialize TOTP manager with configured durations."""
        self.durations = settings.totp_durations
        self.secret_length = settings.totp_secret_length
        self._totp_generators: Dict[str, pyotp.TOTP] = {}
        # Use data directory for persistence in Docker
        data_dir = Path("/app/data") if Path("/app/data").exists() else Path(".")
        self.secrets_file = data_dir / "totp_secrets.json"
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
    
    def _save_secrets(self, secrets: Dict[str, str]):
        """Save TOTP secrets to file."""
        try:
            with open(self.secrets_file, 'w') as f:
                json.dump(secrets, f, indent=2)
                logger.info("TOTP secrets saved to file")
        except Exception as e:
            logger.error(f"Failed to save TOTP secrets: {e}")
    
    def _setup_generators(self):
        """Set up TOTP generators for each duration."""
        # Load existing secrets or create new ones
        existing_secrets = self._load_secrets()
        secrets_to_save = {}
        has_new_secrets = False
        
        for duration_key in self.durations.keys():
            if duration_key in existing_secrets:
                # Use existing secret
                secret = existing_secrets[duration_key]
                logger.info(f"Using existing TOTP secret for {duration_key}")
            else:
                # Generate a new secret for this duration
                secret = self._generate_secret()
                logger.info(f"Generated new TOTP secret for {duration_key}")
                has_new_secrets = True
            
            secrets_to_save[duration_key] = secret
            totp = pyotp.TOTP(secret)
            self._totp_generators[duration_key] = totp
        
        # Only save secrets if we generated new ones
        if has_new_secrets:
            self._save_secrets(secrets_to_save)
    
    def _generate_secret(self) -> str:
        """Generate a cryptographically secure random secret."""
        return pyotp.random_base32(length=self.secret_length)
    
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
        for duration_key, totp_gen in self._totp_generators.items():
            if totp_gen.verify(code, valid_window=1):
                duration_seconds = self.durations[duration_key]
                logger.info(f"Valid TOTP code for {duration_key} duration")
                return (duration_key, duration_seconds)
        
        logger.warning(f"Invalid TOTP code provided: {code}")
        return None
    
    def get_expiry_time(self, duration_seconds: int) -> Optional[datetime]:
        """
        Calculate expiry time for a given duration.
        
        Args:
            duration_seconds: Duration in seconds (-1 for forever)
            
        Returns:
            Expiry datetime or None for forever access
        """
        if duration_seconds == -1:  # Forever access
            return None
        
        return datetime.utcnow() + timedelta(seconds=duration_seconds)
    
    def get_generator_secrets(self) -> Dict[str, str]:
        """
        Get the secrets for all TOTP generators (for QR code generation).
        
        Returns:
            Dictionary mapping duration keys to their base32 secrets
        """
        secrets_dict = {}
        for duration_key, totp_gen in self._totp_generators.items():
            secrets_dict[duration_key] = totp_gen.secret
        return secrets_dict
    
    def get_provisioning_uris(self, issuer: str = "HomeguardGuard") -> Dict[str, str]:
        """
        Get provisioning URIs for QR code generation.
        
        Args:
            issuer: The issuer name for the TOTP
            
        Returns:
            Dictionary mapping duration keys to provisioning URIs
        """
        uris = {}
        for duration_key, totp_gen in self._totp_generators.items():
            account_name = f"HomeguardGuard-{duration_key}"
            uri = totp_gen.provisioning_uri(
                name=account_name,
                issuer_name=issuer
            )
            uris[duration_key] = uri
        return uris
    
    def regenerate_secret(self, duration_key: str) -> bool:
        """
        Regenerate secret for a specific duration.
        
        Args:
            duration_key: The duration key to regenerate
            
        Returns:
            True if successful, False if duration_key not found
        """
        if duration_key not in self.durations:
            logger.error(f"Invalid duration key: {duration_key}")
            return False
        
        secret = self._generate_secret()
        totp = pyotp.TOTP(secret)
        self._totp_generators[duration_key] = totp
        
        logger.info(f"Secret regenerated for {duration_key}")
        return True
    
    def get_time_remaining(self) -> int:
        """
        Get the time remaining until the next TOTP code change.
        
        Returns:
            Seconds until next code change
        """
        # TOTP codes change every 30 seconds by default
        current_time = datetime.utcnow().timestamp()
        return 30 - int(current_time % 30)


# Global TOTP manager instance
totp_manager = TOTPManager()