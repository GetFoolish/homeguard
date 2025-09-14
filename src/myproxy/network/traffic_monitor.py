"""Main TrafficMonitor service with auto-recovery capabilities."""

import asyncio
import logging
import signal
import json
from datetime import datetime
from typing import Dict, Set, Optional
from dataclasses import dataclass, asdict

from ..database.connection import db_manager, get_session
from ..database.models import Device, AccessLog
from ..auth.totp import totp_manager
from ..config.settings import settings
from ..phases.phase_manager import phase_manager
from .enhanced_filter import enhanced_filter
from ..integrations.sheets import sheets_manager

logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """Represents a network device."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_authorized: bool = False


class TrafficMonitor:
    """
    Main service that monitors and controls network traffic.
    Includes auto-recovery mechanisms for power outages and crashes.
    """
    
    def __init__(self):
        """Initialize TrafficMonitor with auto-recovery capabilities."""
        self.is_running = False
        self.connected_devices: Dict[str, NetworkDevice] = {}
        self.authorized_devices: Set[str] = set()
        self.health_check_task: Optional[asyncio.Task] = None
        self.device_cleanup_task: Optional[asyncio.Task] = None
        self.restart_attempts = 0
        self.max_restart_attempts = settings.max_restart_attempts
        # Track HomeGuard-created iptables rules for cleanup
        self.managed_rules: Set[str] = set()
        
    async def start(self):
        """Start the TrafficMonitor service."""
        try:
            logger.info("Starting TrafficMonitor service...")
            
            # Initialize database
            await db_manager.initialize()
            
            # Initialize phase management system
            await phase_manager.start()
            
            # Initialize enhanced traffic filtering
            await enhanced_filter.start()
            
            # Initialize Google Sheets integration
            await sheets_manager.start()
            
            # Restore state from previous session (crash recovery)
            await self._restore_state()
            
            # Set up signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
            # Clean up any stale rules from previous sessions
            await self.cleanup_stale_rules_on_startup()

            # Set up traffic filtering (iptables)
            await self._setup_traffic_filtering()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self.is_running = True
            self.restart_attempts = 0  # Reset restart counter on successful start
            
            logger.info("TrafficMonitor service started successfully")
            
            # Main service loop
            await self._run_service_loop()
            
        except Exception as e:
            logger.error(f"Failed to start TrafficMonitor: {e}")
            if settings.auto_recovery and self.restart_attempts < self.max_restart_attempts:
                await self._attempt_restart()
            else:
                raise
    
    async def stop(self):
        """Stop the TrafficMonitor service gracefully."""
        logger.info("Stopping TrafficMonitor service...")
        
        self.is_running = False
        
        # Cancel background tasks
        if self.health_check_task:
            self.health_check_task.cancel()
        if self.device_cleanup_task:
            self.device_cleanup_task.cancel()
        
        # Stop phase management system
        await phase_manager.stop()
        
        # Stop enhanced traffic filtering
        await enhanced_filter.stop()
        
        # Stop Google Sheets integration
        await sheets_manager.stop()
        
        # Clean up iptables rules
        await self.cleanup_iptables_on_shutdown()
        
        # Backup current state before shutdown
        await self._backup_state()
        
        logger.info("TrafficMonitor service stopped gracefully")
    
    async def _restore_state(self):
        """Restore service state after crash or restart."""
        try:
            logger.info("Restoring service state...")
            
            # Restore authorized devices from database
            async with db_manager.session_maker() as session:
                from sqlalchemy import select
                
                # Get all authorized devices
                stmt = select(Device).where(Device.is_authorized == True)
                result = await session.execute(stmt)
                devices = result.scalars().all()
                
                for device in devices:
                    # Check if access is still valid
                    if device.is_access_valid:
                        self.authorized_devices.add(device.mac_address)
                        self.connected_devices[device.mac_address] = NetworkDevice(
                            mac_address=device.mac_address,
                            ip_address=device.ip_address,
                            hostname=device.hostname,
                            first_seen=device.first_seen,
                            last_seen=device.last_seen,
                            is_authorized=True
                        )
                        logger.info(f"Restored authorized device: {device.mac_address}")
                    else:
                        # Revoke expired access
                        device.revoke_access()
                        logger.info(f"Revoked expired access for device: {device.mac_address}")
                
                await session.commit()
            
            # Restore system configuration from backup
            config_backup = await db_manager.restore_state("service_config")
            if config_backup:
                config_data = json.loads(config_backup)
                logger.info(f"Restored service configuration: {len(config_data)} settings")
            
            logger.info(f"State restoration complete. {len(self.authorized_devices)} authorized devices restored")
            
        except Exception as e:
            logger.error(f"Failed to restore state: {e}")
            # Continue startup even if state restoration fails
    
    async def _backup_state(self):
        """Backup current service state for crash recovery."""
        try:
            # Backup service configuration
            config_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "authorized_devices_count": len(self.authorized_devices),
                "connected_devices_count": len(self.connected_devices),
                "service_uptime": datetime.utcnow().isoformat()
            }
            
            await db_manager.backup_state("service_config", json.dumps(config_data))
            logger.debug("Service state backed up successfully")
            
        except Exception as e:
            logger.error(f"Failed to backup state: {e}")
    
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def _start_background_tasks(self):
        """Start background monitoring tasks."""
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        self.device_cleanup_task = asyncio.create_task(self._device_cleanup_loop())
        
        logger.info("Background monitoring tasks started")
    
    async def _run_service_loop(self):
        """Main service loop for traffic monitoring."""
        logger.info("Entering main service loop")
        
        while self.is_running:
            try:
                # Simulate network device discovery (replace with actual implementation)
                await self._discover_devices()
                
                # Monitor traffic for authorized devices
                await self._monitor_traffic()
                
                # Backup state periodically
                await self._backup_state()
                
                # Sleep before next iteration
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in service loop: {e}")
                if settings.auto_recovery:
                    await asyncio.sleep(5)  # Brief pause before retry
                else:
                    raise
    
    async def _discover_devices(self):
        """Discover connected network devices."""
        # This is a simulation - in real implementation, this would:
        # - Monitor ARP table
        # - Listen for DHCP requests
        # - Scan network interfaces
        
        # For now, just log that device discovery is running
        # logger.debug("Running device discovery...")
        pass
    
    async def _monitor_traffic(self):
        """Monitor network traffic and enforce authentication-based filtering."""
        try:
            # Check for expired device sessions and revoke access
            expired_devices = []
            
            async with db_manager.session_maker() as session:
                from sqlalchemy import select
                
                # Get all authorized devices from database
                stmt = select(Device).where(Device.is_authorized == True)
                result = await session.execute(stmt)
                devices = result.scalars().all()
                
                for device in devices:
                    # Check if access has expired
                    if not device.is_access_valid:
                        expired_devices.append(device.mac_address)
                        device.revoke_access()
                        logger.info(f"Revoking expired access for device: {device.mac_address}")
                
                if expired_devices:
                    await session.commit()
            
            # Block traffic for expired devices
            for mac_address in expired_devices:
                if mac_address in self.authorized_devices:
                    self.authorized_devices.remove(mac_address)
                
                if mac_address in self.connected_devices:
                    device = self.connected_devices[mac_address]
                    device.is_authorized = False
                    
                    # Block the device's traffic
                    if device.ip_address:
                        await self.block_device_traffic(mac_address, device.ip_address)
            
            # Monitor for new unauthorized traffic attempts
            await self._check_unauthorized_traffic()
            
        except Exception as e:
            logger.error(f"Error monitoring traffic: {e}")
    
    async def _health_check_loop(self):
        """Background task for health monitoring."""
        while self.is_running:
            try:
                # Check database health
                db_healthy = await db_manager.health_check()
                if not db_healthy:
                    logger.error("Database health check failed")
                
                # Check TOTP system
                current_codes = totp_manager.generate_current_codes()
                if not current_codes:
                    logger.error("TOTP system health check failed")
                
                # Sleep until next health check
                await asyncio.sleep(settings.health_check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(settings.health_check_interval)
    
    async def _device_cleanup_loop(self):
        """Background task for cleaning up expired devices."""
        while self.is_running:
            try:
                # First check database for expired devices and revoke their access
                async with db_manager.session_maker() as session:
                    from sqlalchemy import select
                    from datetime import datetime

                    # Find devices with expired access
                    stmt = select(Device).where(
                        Device.is_authorized == True,
                        Device.access_expires_at != None,
                        Device.access_expires_at < datetime.utcnow()
                    )
                    result = await session.execute(stmt)
                    expired_devices = result.scalars().all()

                    # Revoke access for expired devices (this will update iptables rules)
                    for device in expired_devices:
                        logger.info(f"⏰ Device {device.mac_address} access expired, revoking access")
                        await self.revoke_device_access(device.mac_address, device.ip_address)

                # Run database cleanup
                await db_manager.cleanup_expired_devices()

                # Remove expired devices from memory
                expired_macs = []
                for mac, device in self.connected_devices.items():
                    if not device.is_authorized:
                        expired_macs.append(mac)

                for mac in expired_macs:
                    if mac in self.connected_devices:
                        del self.connected_devices[mac]
                    if mac in self.authorized_devices:
                        self.authorized_devices.remove(mac)

                # Sleep until next cleanup
                await asyncio.sleep(300)  # Clean up every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Device cleanup error: {e}")
                await asyncio.sleep(300)
    
    async def _attempt_restart(self):
        """Attempt to restart the service after a failure."""
        self.restart_attempts += 1
        logger.warning(f"Attempting service restart ({self.restart_attempts}/{self.max_restart_attempts})")
        
        await asyncio.sleep(5)  # Brief delay before restart
        
        try:
            await self.start()
        except Exception as e:
            logger.error(f"Restart attempt {self.restart_attempts} failed: {e}")
            if self.restart_attempts < self.max_restart_attempts:
                await self._attempt_restart()
            else:
                logger.critical("Maximum restart attempts reached. Service failed permanently.")
                raise
    
    async def authenticate_device(self, mac_address: str, totp_code: str, user_agent: str = None, device_info: dict = None) -> tuple[bool, str]:
        """
        Authenticate a device using TOTP code.
        
        Args:
            mac_address: Device MAC address
            totp_code: TOTP code provided by user
            user_agent: Browser user agent string
            device_info: Additional device information (IP, hostname, device type, etc.)
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Validate TOTP code
            validation_result = totp_manager.validate_code(totp_code)
            
            if not validation_result:
                await self._log_access_attempt(mac_address, "auth_failed", f"Invalid TOTP: {totp_code}")
                return False, "Invalid TOTP code"
            
            duration_key, duration_seconds = validation_result
            expiry_time = totp_manager.get_expiry_time(duration_seconds)
            
            # Update device in database
            async with db_manager.session_maker() as session:
                device = await session.get(Device, mac_address)
                if not device:
                    device = Device(mac_address=mac_address)
                    session.add(device)
                
                device.grant_access(duration_key, expiry_time)
                device.last_seen = datetime.utcnow()
                
                # Update device information from device_info or fallback to user_agent
                if device_info:
                    device.ip_address = device_info.get("ip_address")
                    device.hostname = device_info.get("hostname")
                    device.device_type = device_info.get("device_type")
                    device.user_agent = device_info.get("user_agent") or user_agent
                elif user_agent:
                    device.user_agent = user_agent
                
                await session.commit()
            
            # Update in-memory state
            self.authorized_devices.add(mac_address)
            if mac_address in self.connected_devices:
                self.connected_devices[mac_address].is_authorized = True
            
            # Allow traffic for this device
            client_ip = None

            # First priority: Use IP from device_info if available
            if device_info and device_info.get("ip_address"):
                client_ip = device_info.get("ip_address")
                await self.allow_device_traffic(mac_address, client_ip)
                logger.info(f"✅ Allowed traffic for device {mac_address} using provided IP {client_ip}")

            # Handle double NAT situation - check if device is behind NAT router
            elif device_info and device_info.get("is_behind_nat"):
                nat_router_ip = device_info.get("nat_router_ip")
                logger.info(f"🔍 Device {mac_address} is behind NAT router {nat_router_ip}")

                # For NAT'd devices, allow traffic from the NAT router IP
                client_ip = nat_router_ip
                await self.allow_device_traffic(mac_address, client_ip)
                logger.info(f"✅ Allowed traffic from NAT router {client_ip} for device {mac_address}")

            else:
                # Fallback: try to get IP from MAC (this usually fails)
                client_ip = self._get_client_ip_from_mac(mac_address)
                if client_ip:
                    await self.allow_device_traffic(mac_address, client_ip)
                    logger.info(f"✅ Allowed traffic for device {mac_address} using resolved IP {client_ip}")
                else:
                    logger.error(f"❌ Could not determine IP for MAC {mac_address} - traffic filtering will not work!")
            
            await self._log_access_attempt(mac_address, "auth_success", f"Granted {duration_key} access")
            
            duration_text = duration_key.replace('_', ' ')
            return True, f"Access granted for {duration_text}"
            
        except Exception as e:
            logger.error(f"Authentication error for device {mac_address}: {e}")
            return False, "Authentication system error"
    
    async def revoke_device_access(self, mac_address: str, client_ip: str = None) -> bool:
        """
        Revoke access for a specific device.

        Args:
            mac_address: Device MAC address to revoke access for
            client_ip: Optional IP address (if not provided, will look up in database)

        Returns:
            bool: True if successfully revoked, False otherwise
        """
        try:
            # Remove from authorized devices set
            self.authorized_devices.discard(mac_address)

            # Update connected device status
            if mac_address in self.connected_devices:
                self.connected_devices[mac_address].is_authorized = False

            # Get client IP for iptables rule removal
            if not client_ip:
                # Look up IP address from database first
                async with db_manager.session_maker() as session:
                    device = await session.get(Device, mac_address)
                    if device and device.ip_address:
                        client_ip = device.ip_address
                        logger.info(f"Found stored IP {client_ip} for device {mac_address}")
                    else:
                        # Fallback to MAC-to-IP resolution (usually fails)
                        client_ip = self._get_client_ip_from_mac(mac_address)
                        if client_ip:
                            logger.info(f"Resolved IP {client_ip} for device {mac_address}")

            # Block traffic for this device
            if client_ip:
                await self.block_device_traffic(mac_address, client_ip)
                logger.info(f"✅ Revoked access for device {mac_address} (IP: {client_ip})")
            else:
                logger.error(f"❌ Could not determine IP for device {mac_address} - iptables rules not updated!")

            await self._log_access_attempt(mac_address, "access_revoked", "Access revoked by admin")
            logger.info(f"Access revoked for device: {mac_address}")

            return True

        except Exception as e:
            logger.error(f"Error revoking access for device {mac_address}: {e}")
            return False
    
    async def _log_access_attempt(self, mac_address: str, event_type: str, details: str):
        """Log access attempt to database."""
        try:
            async with db_manager.session_maker() as session:
                log_entry = AccessLog(
                    mac_address=mac_address,
                    event_type=event_type,
                    event_details=details,
                    timestamp=datetime.utcnow()
                )
                session.add(log_entry)
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to log access attempt: {e}")

    async def _setup_traffic_filtering(self):
        """Set up iptables rules for transparent proxy filtering."""
        try:
            logger.info("Setting up iptables traffic filtering...")

            # Clear existing rules for our chain
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-F", "MYPROXY_FILTER"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "MYPROXY_FILTER"
            ], ignore_errors=True)

            # Create our custom chains if they don't exist
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-N", "MYPROXY_FILTER"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-N", "MYPROXY_FILTER"
            ], ignore_errors=True)

            # Set default policy to DROP for our filter chain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-P", "MYPROXY_FILTER", "DROP"
            ], ignore_errors=True)

            # Insert MYPROXY_FILTER as the FIRST rule to catch all client traffic
            if not await self._forward_rule_exists():
                await self._run_iptables_command([
                    "iptables", "-t", "filter", "-I", "FORWARD", "1", "-j", "MYPROXY_FILTER"
                ])
                logger.info("✅ Added MYPROXY_FILTER rule to FORWARD chain (position 1)")
            else:
                logger.info("✅ MYPROXY_FILTER rule already exists in FORWARD chain")

            # Add RELATED,ESTABLISHED rule for return traffic (position 2, after MYPROXY_FILTER)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "FORWARD", "2", "-i", "eth0", "-o", "eth1",
                "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], ignore_errors=True)
            logger.info("✅ Added RELATED,ESTABLISHED rule for return traffic")

            # Allow established connections, loopback, and general traffic
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ])

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "2",
                "-i", "lo", "-j", "ACCEPT"
            ])

            # Add general ACCEPT rule for all other traffic (allows internet access)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER", "-j", "ACCEPT"
            ])

            # Apply mode-specific rules based on configuration
            await self._apply_mode_specific_rules()

            logger.info("✅ iptables traffic filtering setup complete")

        except Exception as e:
            logger.error(f"Failed to setup iptables traffic filtering: {e}")
            raise

    async def allow_device_traffic(self, mac_address: str, ip_address: str):
        """Allow traffic for an authenticated device using IP-based iptables rule in MYPROXY_FILTER chain."""
        try:
            # Remove ALL existing rules for this IP (gateway, DNS, and DROP)
            # This ensures clean state before adding ACCEPT rule
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-d", settings.gateway_ip, "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-j", "DROP"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-j", "ACCEPT"
            ], ignore_errors=True)

            # Check if ACCEPT rule already exists (after cleanup)
            if await self._ip_filter_rule_exists(ip_address, "ACCEPT"):
                logger.debug(f"Traffic allow rule already exists for IP {ip_address}")
                return

            # Add ACCEPT rule in MYPROXY_FILTER chain to allow internet access
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1", "-s", ip_address, "-j", "ACCEPT"
            ])

            await self._log_access_attempt(mac_address, "traffic_allowed", f"IP {ip_address}")
            logger.info(f"✅ Internet access granted for IP {ip_address} (MAC: {mac_address})")

        except Exception as e:
            logger.error(f"Failed to allow traffic for IP {ip_address}: {e}")

    async def block_device_traffic(self, mac_address: str, ip_address: str):
        """Block traffic for a device using IP-based iptables rule in MYPROXY_FILTER chain."""
        try:
            # Check if blocking rule already exists
            if await self._ip_filter_rule_exists(ip_address, "DROP"):
                logger.debug(f"Traffic blocking rule already exists for IP {ip_address}")
                return

            # Remove any existing rules for this IP first (ACCEPT rules from previous authentication)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-j", "ACCEPT"
            ], ignore_errors=True)

            # Also remove any leftover gateway/DNS access rules from previous authentication
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-d", settings.gateway_ip, "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-s", ip_address, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ], ignore_errors=True)

            # Add gateway access rule FIRST (must be before DROP rule)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1", "-s", ip_address, "-d", settings.gateway_ip, "-j", "ACCEPT"
            ])

            # Add DNS access rule (must be before DROP rule)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "2", "-s", ip_address, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ])

            # Add DROP rule LAST to block all other internet access
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "3", "-s", ip_address, "-j", "DROP"
            ])

            await self._log_access_attempt(mac_address, "traffic_blocked", f"IP {ip_address}")
            logger.info(f"❌ Internet access blocked for IP {ip_address} (MAC: {mac_address}) - Gateway access allowed")

        except Exception as e:
            logger.error(f"Failed to block traffic for IP {ip_address}: {e}")

    async def _ip_filter_rule_exists(self, ip_address: str, target: str) -> bool:
        """Check if an IP-based MYPROXY_FILTER rule already exists."""
        try:
            import subprocess

            # List the MYPROXY_FILTER chain rules
            result = subprocess.run([
                "iptables", "-t", "filter", "-L", "MYPROXY_FILTER", "--line-numbers", "-v"
            ], capture_output=True, text=True)

            if result.returncode != 0:
                return False

            # Check if our specific IP rule exists
            for line in result.stdout.split('\n'):
                if ip_address in line and target in line:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking MYPROXY_FILTER rule existence: {e}")
            return False

    async def _ip_forward_rule_exists(self, ip_address: str, target: str) -> bool:
        """Check if an IP-based FORWARD rule already exists."""
        try:
            import subprocess

            # List the FORWARD chain rules
            result = subprocess.run([
                "iptables", "-t", "filter", "-L", "FORWARD", "--line-numbers", "-v"
            ], capture_output=True, text=True)

            if result.returncode != 0:
                return False

            # Check if our specific IP rule exists
            for line in result.stdout.split('\n'):
                if ip_address in line and target in line:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking FORWARD rule existence: {e}")
            return False

    async def _forward_rule_exists(self) -> bool:
        """Check if MYPROXY_FILTER rule already exists in FORWARD chain."""
        try:
            # List the FORWARD chain rules
            result = await self._run_iptables_command([
                "iptables", "-t", "filter", "-L", "FORWARD", "--line-numbers", "-n"
            ])

            if not result or not result.stdout:
                return False

            # Handle both string and bytes output
            output = result.stdout.decode('utf-8') if isinstance(result.stdout, bytes) else result.stdout

            # Check if MYPROXY_FILTER rule exists
            return "MYPROXY_FILTER" in output

        except Exception as e:
            logger.error(f"Error checking FORWARD rule existence: {e}")
            return False

    async def _iptables_rule_exists(self, chain: str, ip_address: str, mac_address: str, target: str) -> bool:
        """Check if an iptables rule already exists in the chain."""
        try:
            import subprocess

            # List the chain rules
            result = subprocess.run([
                "iptables", "-t", "filter", "-L", chain, "--line-numbers", "-v"
            ], capture_output=True, text=True)

            if result.returncode != 0:
                return False

            # Check if our specific rule exists
            for line in result.stdout.split('\n'):
                if (ip_address in line and
                    mac_address.upper() in line.upper() and
                    target in line):
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking iptables rule existence: {e}")
            return False

    async def _ensure_nat_forward_rules(self):
        """Ensure essential NAT FORWARD rules exist for router functionality."""
        try:
            logger.info("Checking NAT FORWARD rules...")

            # Check if essential NAT rules exist in FORWARD chain
            result = await self._run_iptables_command(["iptables", "-L", "FORWARD", "-n"])
            output = result.stdout if hasattr(result, 'stdout') else str(result)

            has_eth1_to_eth0 = False
            has_established = False

            for line in output.split('\n'):
                if 'eth1' in line and 'eth0' in line and 'ACCEPT' in line:
                    has_eth1_to_eth0 = True
                if 'ESTABLISHED' in line and 'RELATED' in line and 'ACCEPT' in line:
                    has_established = True

            # Add missing NAT rules if needed
            if not has_eth1_to_eth0:
                await self._run_iptables_command([
                    "iptables", "-I", "FORWARD", "1", "-i", "eth1", "-o", "eth0", "-j", "ACCEPT"
                ])
                logger.info("✅ Added NAT rule: eth1 -> eth0 ACCEPT")

            if not has_established:
                await self._run_iptables_command([
                    "iptables", "-I", "FORWARD", "2", "-i", "eth0", "-o", "eth1",
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
                ])
                logger.info("✅ Added NAT rule: RELATED,ESTABLISHED ACCEPT")

            if has_eth1_to_eth0 and has_established:
                logger.info("✅ Essential NAT FORWARD rules already exist")

        except Exception as e:
            logger.error(f"Failed to ensure NAT FORWARD rules: {e}")
            raise

    async def _apply_mode_specific_rules(self):
        """Apply blocking rules based on current gateway mode."""
        try:
            logger.info(f"Applying mode-specific rules for mode: {settings.gateway_mode}")

            if settings.gateway_mode == "transparent":
                # Mode 3: Transparent mode - no blocking, all traffic allowed
                logger.info("🌐 Transparent mode: All traffic allowed through without filtering")

            elif settings.gateway_mode == "totp_testing":
                # Mode 1: Block specific testing IP only, allow all others
                if settings.testing_ip:
                    logger.info(f"🧪 TOTP Testing mode: Blocking IP {settings.testing_ip}, allowing all others")

                    # Remove the general ACCEPT rule temporarily to insert specific rules
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-j", "ACCEPT"
                    ], ignore_errors=True)

                    # Allow gateway access for testing IP (needed for TOTP auth page)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                        "-s", settings.testing_ip, "-d", settings.gateway_ip, "-j", "ACCEPT"
                    ])

                    # Allow DNS for testing IP (needed for TOTP auth page to load)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                        "-s", settings.testing_ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
                    ])

                    # Block all other internet traffic for testing IP
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                        "-s", settings.testing_ip, "-j", "DROP"
                    ])

                    # Re-add general ACCEPT rule for all other devices (non-testing IPs)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "MYPROXY_FILTER", "-j", "ACCEPT"
                    ])

                    logger.info(f"✅ Testing IP {settings.testing_ip} blocked from internet, gateway accessible for TOTP")
                    logger.info(f"✅ All other devices have full internet access")
                else:
                    logger.warning("TOTP testing mode enabled but no testing_ip configured - no blocking applied")

            elif settings.gateway_mode == "totp_full":
                # Mode 2: Block all devices by default until authenticated
                logger.info("🔒 TOTP Full mode: All devices blocked by default until authentication")

                # Remove the general ACCEPT rule completely (no internet for anyone by default)
                await self._run_iptables_command([
                    "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", "-j", "ACCEPT"
                ], ignore_errors=True)

                logger.info("✅ All devices blocked from internet until TOTP authentication")
                logger.info("✅ Use admin panel to authenticate devices individually")

            else:
                logger.warning(f"Unknown gateway mode: {settings.gateway_mode} - using transparent mode as fallback")

        except Exception as e:
            logger.error(f"Failed to apply mode-specific rules: {e}")
            raise

    async def _run_iptables_command(self, cmd_args: list, ignore_errors: bool = False):
        """Execute an iptables command with proper error handling."""
        try:
            import subprocess
            
            # Run the iptables command
            result = subprocess.run(
                cmd_args, 
                capture_output=True, 
                text=True, 
                check=not ignore_errors
            )
            
            if result.returncode != 0 and not ignore_errors:
                logger.error(f"iptables command failed: {' '.join(cmd_args)}")
                logger.error(f"Error output: {result.stderr}")
                raise Exception(f"iptables command failed with code {result.returncode}")
            
            if result.stdout:
                logger.debug(f"iptables output: {result.stdout.strip()}")
                
            return result
            
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                logger.error(f"iptables command failed: {' '.join(cmd_args)}")
                logger.error(f"Error: {e}")
                raise
        except Exception as e:
            if not ignore_errors:
                logger.error(f"Failed to execute iptables command: {e}")
                raise

    def _get_client_ip_from_mac(self, mac_address: str) -> Optional[str]:
        """Get client IP address from MAC address via ARP table."""
        try:
            import subprocess
            import re
            
            # Check ARP table for MAC address
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if mac_address.lower() in line.lower():
                    # Extract IP address from ARP entry
                    ip_match = re.search(r'\(([\d.]+)\)', line)
                    if ip_match:
                        return ip_match.group(1)
            
            # Fallback: check connected devices
            if mac_address in self.connected_devices:
                return self.connected_devices[mac_address].ip_address
                
            return None
            
        except Exception as e:
            logger.error(f"Failed to get IP for MAC {mac_address}: {e}")
            return None

    async def _check_unauthorized_traffic(self):
        """Check for unauthorized traffic attempts and log them."""
        try:
            # This could be enhanced to read from iptables logs or netfilter logs
            # For now, we rely on the default DROP policy to block unauthorized traffic
            # The iptables rules we set up will automatically DROP any packets that don't
            # match our ACCEPT rules for authorized devices
            
            # Log this as a system health check
            logger.debug("Traffic filtering active - unauthorized traffic blocked by iptables")
            
        except Exception as e:
            logger.error(f"Error checking unauthorized traffic: {e}")

    async def cleanup_stale_rules_on_startup(self):
        """Clean up any stale HomeGuard rules from previous sessions."""
        try:
            logger.info("Cleaning up stale iptables rules from previous sessions...")

            # Remove any existing HomeGuard IP blocking rules in MYPROXY_FILTER
            # These might have been left behind from unclean shutdowns
            import subprocess

            try:
                # Get all rules in MYPROXY_FILTER chain
                result = subprocess.run([
                    "iptables", "-t", "filter", "-L", "MYPROXY_FILTER", "--line-numbers", "-n"
                ], capture_output=True, text=True, check=False)

                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    # Look for rules with specific IPs (our managed rules)
                    # Remove them in reverse order to preserve line numbers
                    rules_to_remove = []

                    for line in lines[2:]:  # Skip header lines
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                # Look for DROP or ACCEPT rules with specific source IPs
                                target = parts[1]
                                source = parts[4] if len(parts) > 4 else ""

                                # Remove rules that look like HomeGuard-managed rules
                                # (DROP/ACCEPT with specific IP sources, not "anywhere")
                                if target in ["DROP", "ACCEPT"] and source != "anywhere" and "." in source:
                                    rule_num = parts[0]
                                    rules_to_remove.append(rule_num)

                    # Remove rules in reverse order to preserve line numbers
                    for rule_num in reversed(rules_to_remove):
                        await self._run_iptables_command([
                            "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", rule_num
                        ], ignore_errors=True)
                        logger.info(f"Removed stale rule #{rule_num} from MYPROXY_FILTER")

            except Exception as e:
                logger.warning(f"Could not clean up stale rules: {e}")

            logger.info("✅ Stale rule cleanup complete")

        except Exception as e:
            logger.error(f"Error during startup cleanup: {e}")

    async def cleanup_iptables_on_shutdown(self):
        """Clean up iptables rules when service shuts down."""
        try:
            logger.info("Cleaning up iptables rules...")
            
            # Remove ALL MYPROXY_FILTER rules from FORWARD chain
            logger.info("Removing all MYPROXY_FILTER rules from FORWARD chain...")
            while True:
                result = await self._run_iptables_command([
                    "iptables", "-t", "filter", "-D", "FORWARD", "-j", "MYPROXY_FILTER"
                ], ignore_errors=True)
                if result and result.returncode != 0:
                    break  # No more rules to remove
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-X", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-F", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-X", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            logger.info("✅ iptables cleanup complete")
            
        except Exception as e:
            logger.error(f"Error cleaning up iptables: {e}")


# Global traffic monitor instance
traffic_monitor = TrafficMonitor()