"""Network device scanner for Homeguard."""

import logging
import subprocess
import re
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger(__name__)


class DeviceScanner:
    """Scans network for active devices using ARP and DHCP leases."""

    def __init__(self):
        """Initialize device scanner."""
        pass

    def scan_arp_table(self) -> List[Dict[str, str]]:
        """Scan ARP table for active devices."""
        devices = []
        try:
            # Use arp -a to get ARP table
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            output = result.stdout

            # Parse ARP output
            # Format: ? (192.168.2.100) at aa:bb:cc:dd:ee:ff on eth1 ifscope [ethernet]
            pattern = r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)'

            for line in output.split('\n'):
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    ip_address = match.group(1)
                    mac_address = match.group(2).lower()

                    devices.append({
                        'ip_address': ip_address,
                        'mac_address': mac_address,
                        'hostname': None
                    })

            logger.info(f"Found {len(devices)} devices in ARP table")
            return devices

        except Exception as e:
            logger.error(f"Error scanning ARP table: {e}")
            return []

    def scan_dhcp_leases(self) -> List[Dict[str, str]]:
        """Scan DHCP leases file for devices."""
        devices = []
        lease_file = "/var/lib/misc/dnsmasq.leases"

        try:
            with open(lease_file, 'r') as f:
                for line in f:
                    # dnsmasq lease format: timestamp mac ip hostname client-id
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        devices.append({
                            'ip_address': parts[2],
                            'mac_address': parts[1].lower(),
                            'hostname': parts[3] if parts[3] != '*' else None
                        })

            logger.info(f"Found {len(devices)} devices in DHCP leases")
            return devices

        except FileNotFoundError:
            logger.warning(f"DHCP lease file not found: {lease_file}")
            return []
        except Exception as e:
            logger.error(f"Error reading DHCP leases: {e}")
            return []

    def get_all_devices(self) -> List[Dict[str, str]]:
        """Get all active devices from ARP and DHCP."""
        all_devices = {}

        # Get devices from ARP
        for device in self.scan_arp_table():
            key = device['ip_address']
            all_devices[key] = device

        # Merge with DHCP leases (prefer DHCP hostname if available)
        for device in self.scan_dhcp_leases():
            key = device['ip_address']
            if key in all_devices:
                # Update hostname if we got it from DHCP
                if device['hostname']:
                    all_devices[key]['hostname'] = device['hostname']
            else:
                all_devices[key] = device

        logger.info(f"Total unique devices found: {len(all_devices)}")
        return list(all_devices.values())


# Global scanner instance
device_scanner = DeviceScanner()
