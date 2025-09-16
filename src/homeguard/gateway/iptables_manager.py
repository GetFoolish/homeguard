"""IPTables management for gateway modes."""

import subprocess
import logging
from typing import List
from .config import GatewayConfig, GatewayMode

logger = logging.getLogger(__name__)


class IptablesManager:
    """Manage iptables rules for different gateway modes."""

    def __init__(self, config: GatewayConfig):
        self.config = config

    def list_authenticated_devices(self) -> List[str]:
        """List MAC addresses of authenticated devices."""
        try:
            # This would normally query iptables for devices with ACCEPT rules
            # For now, return empty list as a placeholder
            return []
        except Exception as e:
            logger.error(f"Error listing authenticated devices: {e}")
            return []

    def add_device_rule(self, mac_address: str, allow: bool = True):
        """Add iptables rule for device."""
        try:
            action = "ACCEPT" if allow else "DROP"
            # Placeholder for actual iptables commands
            logger.info(f"Would add iptables rule: {mac_address} -> {action}")
        except Exception as e:
            logger.error(f"Error adding device rule: {e}")

    def remove_device_rule(self, mac_address: str):
        """Remove iptables rule for device."""
        try:
            # Placeholder for actual iptables commands
            logger.info(f"Would remove iptables rule for: {mac_address}")
        except Exception as e:
            logger.error(f"Error removing device rule: {e}")

    def apply_mode_rules(self, mode: GatewayMode):
        """Apply iptables rules for the specified mode."""
        try:
            if mode == GatewayMode.TRANSPARENT:
                self._apply_transparent_rules()
            elif mode == GatewayMode.TOTP_ENABLED:
                self._apply_totp_rules()
            logger.info(f"Applied {mode.value} mode rules")
        except Exception as e:
            logger.error(f"Error applying mode rules: {e}")

    def _apply_transparent_rules(self):
        """Apply rules for transparent mode (allow all traffic)."""
        # These rules would be applied in transparent mode
        logger.info("Applying transparent mode rules (allow all)")

    def _apply_totp_rules(self):
        """Apply rules for TOTP mode (block until authenticated)."""
        # These rules would block traffic until TOTP authentication
        logger.info("Applying TOTP mode rules (block until auth)")