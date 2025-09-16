"""Gateway configuration management."""

from enum import Enum
from ..config.settings import settings
import json
import os
import logging

logger = logging.getLogger(__name__)

class GatewayMode(Enum):
    """Gateway operating modes."""
    TRANSPARENT = "transparent"
    TOTP_ENABLED = "totp_enabled"


class GatewayConfig:
    """Gateway configuration manager."""

    def __init__(self):
        self.config_file = "/tmp/homeguard_gateway.json"

    def get_mode(self) -> GatewayMode:
        """Get current gateway mode."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    mode = config.get('mode', settings.gateway_mode)
                    return GatewayMode(mode)
            return GatewayMode(settings.gateway_mode)
        except Exception as e:
            logger.error(f"Error reading gateway mode: {e}")
            return GatewayMode.TRANSPARENT

    def set_mode(self, mode: GatewayMode):
        """Set gateway mode."""
        try:
            config = {"mode": mode.value}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
            logger.info(f"Gateway mode set to: {mode.value}")
        except Exception as e:
            logger.error(f"Error setting gateway mode: {e}")

    def is_emergency_mode(self) -> bool:
        """Check if emergency mode is active."""
        return settings.emergency_mode or os.path.exists("/tmp/homeguard_emergency")

    def enable_emergency_mode(self):
        """Enable emergency transparent mode."""
        try:
            with open("/tmp/homeguard_emergency", 'w') as f:
                f.write("emergency_mode_active")
            logger.warning("Emergency mode enabled")
        except Exception as e:
            logger.error(f"Error enabling emergency mode: {e}")

    def disable_emergency_mode(self):
        """Disable emergency mode."""
        try:
            if os.path.exists("/tmp/homeguard_emergency"):
                os.remove("/tmp/homeguard_emergency")
            logger.info("Emergency mode disabled")
        except Exception as e:
            logger.error(f"Error disabling emergency mode: {e}")

    def get_network_interfaces(self) -> dict:
        """Get network interface configuration."""
        return {
            "wan": "eth0",
            "lan": settings.gateway_interface
        }

    def get_service_ports(self) -> dict:
        """Get service port configuration."""
        return {
            "admin": settings.web_port,
            "proxy": 8080,
            "ssh": 22
        }