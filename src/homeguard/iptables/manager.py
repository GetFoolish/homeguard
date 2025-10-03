"""IPTables management for Homeguard with testing mode support."""

import logging
import subprocess
from typing import List
from ..config.settings import settings

logger = logging.getLogger(__name__)


class IPTablesManager:
    """Manages iptables rules with testing mode support."""

    def __init__(self):
        """Initialize iptables manager."""
        self.execution_mode = settings.execution_mode
        self.lan_interface = settings.lan_interface
        self.wan_interface = settings.wan_interface
        self.gateway_ip = settings.gateway_ip

    def _execute_command(self, command: str) -> bool:
        """Execute a command or print it in testing mode."""
        if self.execution_mode == "testing":
            logger.info(f"[TESTING MODE] Would execute: {command}")
            return True
        else:
            try:
                subprocess.run(command, shell=True, check=True)
                logger.info(f"Executed: {command}")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to execute: {command}, Error: {e}")
                return False

    def set_transparent_mode(self) -> bool:
        """Set iptables to transparent mode (all traffic allowed)."""
        logger.info("Setting iptables to TRANSPARENT mode...")

        commands = [
            # Flush all rules
            "iptables -t filter -F",
            "iptables -t nat -F PREROUTING",
            "iptables -t nat -F POSTROUTING",
            "iptables -t mangle -F 2>/dev/null || true",

            # Delete custom chains
            "iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true",
            "iptables -t filter -X IOT_DEVICE_FILTER 2>/dev/null || true",

            # Set permissive policies
            "iptables -t filter -P INPUT ACCEPT",
            "iptables -t filter -P FORWARD ACCEPT",
            "iptables -t filter -P OUTPUT ACCEPT",

            # Allow admin access
            f"iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,{settings.web_port} -j ACCEPT",
            f"iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,{settings.web_port} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # Allow all LAN to WAN traffic
            f"iptables -t filter -A FORWARD -i {self.lan_interface} -o {self.wan_interface} -j ACCEPT",
            f"iptables -t filter -A FORWARD -i {self.wan_interface} -o {self.lan_interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # NAT for internet access
            f"iptables -t nat -A POSTROUTING -o {self.wan_interface} -j MASQUERADE",

            # Captive portal redirect
            f"iptables -t nat -A PREROUTING -i {self.lan_interface} -p tcp --dport 80 -j REDIRECT --to-port {settings.web_port}",
        ]

        for cmd in commands:
            if not self._execute_command(cmd):
                return False

        logger.info("✅ Transparent mode configured successfully")
        return True

    def set_totp_mode(self, iot_devices: List[str] = None, granted_devices: List[str] = None) -> bool:
        """
        Set iptables to TOTP mode with IOT and granted device support.

        Args:
            iot_devices: List of IOT device IP addresses
            granted_devices: List of granted device IP addresses
        """
        logger.info("Setting iptables to TOTP mode...")

        if iot_devices is None:
            iot_devices = []
        if granted_devices is None:
            granted_devices = []

        commands = [
            # Flush all rules
            "iptables -t filter -F",
            "iptables -t nat -F PREROUTING",
            "iptables -t nat -F POSTROUTING",
            "iptables -t mangle -F 2>/dev/null || true",

            # Delete custom chains
            "iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true",
            "iptables -t filter -X IOT_DEVICE_FILTER 2>/dev/null || true",

            # Create custom chains
            "iptables -t filter -N HOMEGUARD_FILTER",
            "iptables -t filter -N IOT_DEVICE_FILTER",

            # Set restrictive policies (block by default)
            "iptables -t filter -P FORWARD DROP",

            # Allow admin access (SSH, VNC, Web Admin)
            f"iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,{settings.web_port} -j ACCEPT",
            f"iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,{settings.web_port} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # Allow access to gateway IP
            f"iptables -t filter -A FORWARD -d {self.gateway_ip} -j ACCEPT",
        ]

        # Add IOT devices to IOT chain
        for iot_ip in iot_devices:
            commands.append(f"iptables -t filter -A IOT_DEVICE_FILTER -s {iot_ip} -j ACCEPT")

        # Add granted devices to HOMEGUARD chain
        for granted_ip in granted_devices:
            commands.append(f"iptables -t filter -A HOMEGUARD_FILTER -s {granted_ip} -j ACCEPT")

        # Apply chains to FORWARD
        commands.extend([
            f"iptables -t filter -A FORWARD -i {self.lan_interface} -o {self.wan_interface} -j IOT_DEVICE_FILTER",
            f"iptables -t filter -A FORWARD -i {self.lan_interface} -o {self.wan_interface} -j HOMEGUARD_FILTER",

            # Allow return traffic
            f"iptables -t filter -A FORWARD -i {self.wan_interface} -o {self.lan_interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # NAT for internet access
            f"iptables -t nat -A POSTROUTING -o {self.wan_interface} -j MASQUERADE",

            # Captive portal redirect
            f"iptables -t nat -A PREROUTING -i {self.lan_interface} -p tcp --dport 80 -j REDIRECT --to-port {settings.web_port}",
        ])

        for cmd in commands:
            if not self._execute_command(cmd):
                return False

        logger.info(f"✅ TOTP mode configured successfully (IOT: {len(iot_devices)}, Granted: {len(granted_devices)})")
        return True

    def grant_access_to_ip(self, ip_address: str) -> bool:
        """Grant access to a specific IP address."""
        logger.info(f"Granting access to IP: {ip_address}")
        cmd = f"iptables -t filter -A HOMEGUARD_FILTER -s {ip_address} -j ACCEPT"
        return self._execute_command(cmd)

    def block_access_to_ip(self, ip_address: str) -> bool:
        """Block access from a specific IP address."""
        logger.info(f"Blocking access from IP: {ip_address}")
        cmd = f"iptables -t filter -D HOMEGUARD_FILTER -s {ip_address} -j ACCEPT 2>/dev/null || true"
        return self._execute_command(cmd)

    def add_iot_device(self, ip_address: str) -> bool:
        """Add IOT device to IOT chain."""
        logger.info(f"Adding IOT device: {ip_address}")
        cmd = f"iptables -t filter -A IOT_DEVICE_FILTER -s {ip_address} -j ACCEPT"
        return self._execute_command(cmd)

    def remove_iot_device(self, ip_address: str) -> bool:
        """Remove IOT device from IOT chain."""
        logger.info(f"Removing IOT device: {ip_address}")
        cmd = f"iptables -t filter -D IOT_DEVICE_FILTER -s {ip_address} -j ACCEPT 2>/dev/null || true"
        return self._execute_command(cmd)


# Global iptables manager instance
iptables_manager = IPTablesManager()
