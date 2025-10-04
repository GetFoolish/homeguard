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
        # Don't cache settings - read dynamically to support command-line arg overrides
        pass

    @property
    def execution_mode(self) -> str:
        """Get current execution mode from settings (supports runtime changes)."""
        return settings.execution_mode

    @property
    def lan_interface(self) -> str:
        """Get LAN interface from settings."""
        return settings.lan_interface

    @property
    def wan_interface(self) -> str:
        """Get WAN interface from settings."""
        return settings.wan_interface

    @property
    def gateway_ip(self) -> str:
        """Get gateway IP from settings."""
        return settings.gateway_ip

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
        """Set iptables to transparent mode with two-chain architecture (all traffic allowed by default)."""
        logger.info("Setting iptables to TRANSPARENT mode...")

        commands = [
            # Flush all rules
            "iptables -t filter -F",
            "iptables -t nat -F PREROUTING",
            "iptables -t nat -F POSTROUTING",
            "iptables -t mangle -F 2>/dev/null || true",

            # Delete old custom chains
            "iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true",
            "iptables -t filter -X IOT_DEVICE_FILTER 2>/dev/null || true",
            "iptables -t filter -X HOMEGUARD_ACCEPT 2>/dev/null || true",
            "iptables -t filter -X HOMEGUARD_BLOCK 2>/dev/null || true",

            # Create new two-chain architecture
            "iptables -t filter -N HOMEGUARD_ACCEPT",
            "iptables -t filter -N HOMEGUARD_BLOCK",

            # Set permissive policies
            "iptables -t filter -P INPUT ACCEPT",
            "iptables -t filter -P FORWARD ACCEPT",
            "iptables -t filter -P OUTPUT ACCEPT",

            # Allow admin access (SSH, VNC, Web)
            f"iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,{settings.web_port} -j ACCEPT",
            f"iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,{settings.web_port} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # Apply custom chains (fast path empty, block path for manual blocks)
            "iptables -t filter -A FORWARD -j HOMEGUARD_ACCEPT",
            "iptables -t filter -A FORWARD -j HOMEGUARD_BLOCK",

            # Allow all LAN to WAN traffic (default transparent behavior)
            f"iptables -t filter -A FORWARD -i {self.lan_interface} -o {self.wan_interface} -j ACCEPT",
            f"iptables -t filter -A FORWARD -i {self.wan_interface} -o {self.lan_interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # NAT for internet access
            f"iptables -t nat -A POSTROUTING -o {self.wan_interface} -j MASQUERADE",

            # Captive portal redirect
            f"iptables -t nat -A PREROUTING -i {self.lan_interface} -p tcp --dport 80 -j REDIRECT --to-port {settings.web_port}",

            # Initialize chains (ACCEPT empty, BLOCK empty for now)
            "iptables -t filter -A HOMEGUARD_ACCEPT -j RETURN",
        ]

        for cmd in commands:
            if not self._execute_command(cmd):
                return False

        logger.info("✅ Transparent mode configured successfully (two-chain architecture)")
        return True

    def set_totp_mode(self, iot_devices: List[str] = None, granted_devices: List[str] = None) -> bool:
        """
        Set iptables to TOTP mode with two-chain architecture (block by default, allow authenticated).

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

            # Delete old custom chains
            "iptables -t filter -X HOMEGUARD_FILTER 2>/dev/null || true",
            "iptables -t filter -X IOT_DEVICE_FILTER 2>/dev/null || true",
            "iptables -t filter -X HOMEGUARD_ACCEPT 2>/dev/null || true",
            "iptables -t filter -X HOMEGUARD_BLOCK 2>/dev/null || true",

            # Create new two-chain architecture
            "iptables -t filter -N HOMEGUARD_ACCEPT",
            "iptables -t filter -N HOMEGUARD_BLOCK",

            # Set restrictive policies (block by default)
            "iptables -t filter -P FORWARD DROP",

            # Allow admin access (SSH, VNC, Web)
            f"iptables -t filter -A FORWARD -p tcp -m multiport --dports 22,5900,{settings.web_port} -j ACCEPT",
            f"iptables -t filter -A FORWARD -p tcp -m multiport --sports 22,5900,{settings.web_port} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # Apply custom chains (fast path for allowed, slow path blocks rest)
            "iptables -t filter -A FORWARD -j HOMEGUARD_ACCEPT",
            "iptables -t filter -A FORWARD -j HOMEGUARD_BLOCK",

            # Allow return traffic
            f"iptables -t filter -A FORWARD -i {self.wan_interface} -o {self.lan_interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

            # NAT for internet access
            f"iptables -t nat -A POSTROUTING -o {self.wan_interface} -j MASQUERADE",

            # Captive portal redirect
            f"iptables -t nat -A PREROUTING -i {self.lan_interface} -p tcp --dport 80 -j REDIRECT --to-port {settings.web_port}",
        ]

        # Add IOT devices to HOMEGUARD_ACCEPT fast path (using INSERT for O(1) performance)
        for iot_ip in iot_devices:
            # Outbound traffic from IOT device
            commands.append(f"iptables -t filter -I HOMEGUARD_ACCEPT 1 -s {iot_ip} -j ACCEPT")
            # Return traffic to IOT device
            commands.append(f"iptables -t filter -I HOMEGUARD_ACCEPT 2 -d {iot_ip} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

        # Add granted devices to HOMEGUARD_ACCEPT fast path (using INSERT for O(1) performance)
        for granted_ip in granted_devices:
            # Outbound traffic from granted device
            commands.append(f"iptables -t filter -I HOMEGUARD_ACCEPT 1 -s {granted_ip} -j ACCEPT")
            # Return traffic to granted device
            commands.append(f"iptables -t filter -I HOMEGUARD_ACCEPT 2 -d {granted_ip} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

        # Add catch-all DROP to HOMEGUARD_BLOCK (blocks all non-authenticated traffic)
        commands.append("iptables -t filter -A HOMEGUARD_BLOCK -j DROP")

        for cmd in commands:
            if not self._execute_command(cmd):
                return False

        logger.info(f"✅ TOTP mode configured successfully - two-chain architecture (IOT: {len(iot_devices)}, Granted: {len(granted_devices)})")
        return True

    def grant_access_to_ip(self, ip_address: str) -> bool:
        """Grant access to a specific IP address using fast-path (bidirectional, O(1) performance)."""
        logger.info(f"Granting access to IP: {ip_address}")

        # Remove from block list first (if in transparent mode and was blocked)
        self._execute_command(f"iptables -t filter -D HOMEGUARD_BLOCK -s {ip_address} -j DROP 2>/dev/null || true")

        # Add to fast path using INSERT (positions 1 and 2 for O(1) performance)
        # Outbound traffic from device
        cmd1 = f"iptables -t filter -I HOMEGUARD_ACCEPT 1 -s {ip_address} -j ACCEPT"
        # Return traffic to device
        cmd2 = f"iptables -t filter -I HOMEGUARD_ACCEPT 2 -d {ip_address} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        return self._execute_command(cmd1) and self._execute_command(cmd2)

    def block_access_to_ip(self, ip_address: str) -> bool:
        """Block access from a specific IP address (remove from fast-path, add to block list)."""
        logger.info(f"Blocking access from IP: {ip_address}")

        # Remove from fast path (if exists)
        cmd1 = f"iptables -t filter -D HOMEGUARD_ACCEPT -s {ip_address} -j ACCEPT 2>/dev/null || true"
        cmd2 = f"iptables -t filter -D HOMEGUARD_ACCEPT -d {ip_address} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"
        self._execute_command(cmd1)
        self._execute_command(cmd2)

        # In transparent mode, add explicit DROP rule to HOMEGUARD_BLOCK
        # In TOTP mode, this is unnecessary (default policy is DROP)
        if settings.system_mode == "transparent":
            cmd3 = f"iptables -t filter -A HOMEGUARD_BLOCK -s {ip_address} -j DROP"
            return self._execute_command(cmd3)

        return True

    def add_iot_device(self, ip_address: str) -> bool:
        """Add IOT device to HOMEGUARD_ACCEPT fast-path (bidirectional, O(1) performance)."""
        logger.info(f"Adding IOT device: {ip_address}")

        # Remove from block list first (if in transparent mode and was blocked)
        self._execute_command(f"iptables -t filter -D HOMEGUARD_BLOCK -s {ip_address} -j DROP 2>/dev/null || true")

        # Add to fast path using INSERT (positions 1 and 2 for O(1) performance)
        # Outbound traffic from IOT device
        cmd1 = f"iptables -t filter -I HOMEGUARD_ACCEPT 1 -s {ip_address} -j ACCEPT"
        # Return traffic to IOT device
        cmd2 = f"iptables -t filter -I HOMEGUARD_ACCEPT 2 -d {ip_address} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        return self._execute_command(cmd1) and self._execute_command(cmd2)

    def remove_iot_device(self, ip_address: str) -> bool:
        """Remove IOT device from HOMEGUARD_ACCEPT and block if in transparent mode."""
        logger.info(f"Removing IOT device: {ip_address}")

        # Remove from fast path
        cmd1 = f"iptables -t filter -D HOMEGUARD_ACCEPT -s {ip_address} -j ACCEPT 2>/dev/null || true"
        cmd2 = f"iptables -t filter -D HOMEGUARD_ACCEPT -d {ip_address} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"
        self._execute_command(cmd1)
        self._execute_command(cmd2)

        # In transparent mode, this will block the device since it's removed from allow list
        # No need to add explicit DROP in transparent mode for IOT removal (just remove access)
        return True


# Global iptables manager instance
iptables_manager = IPTablesManager()
