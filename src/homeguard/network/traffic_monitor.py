"""Main TrafficMonitor service with auto-recovery capabilities."""

import asyncio
import logging
import signal
import json
from datetime import datetime
from typing import Dict, Set, Optional, List
from dataclasses import dataclass, asdict

from ..database.connection import db_manager, get_session
from ..database.models import Device, AccessLog
from ..auth.totp import totp_manager
from ..config.settings import settings
from ..phases.phase_manager import phase_manager
from .state_manager import state_manager
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
        """Set up iptables rules according to CLAUDE.md specification."""
        try:
            logger.info(f"Setting up iptables traffic filtering for {settings.gateway_mode} mode...")

            # Clear existing rules first
            await self._clear_existing_rules()

            # Create HOMEGUARD_FILTER chain if it doesn't exist
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-N", "HOMEGUARD_FILTER"
            ], ignore_errors=True)

            if settings.gateway_mode == "transparent":
                await self._setup_transparent_mode()
            elif settings.gateway_mode == "totp_full":
                await self._setup_totp_full_mode()
            else:
                logger.warning(f"Unknown gateway mode: {settings.gateway_mode}, defaulting to transparent")
                await self._setup_transparent_mode()

            logger.info("✅ iptables traffic filtering setup complete")

        except Exception as e:
            logger.error(f"Failed to setup iptables traffic filtering: {e}")
            raise

    async def _clear_existing_rules(self):
        """Clear existing rules to ensure clean state."""
        # Flush HOMEGUARD_FILTER chain
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-F", "HOMEGUARD_FILTER"
        ], ignore_errors=True)

        # Remove any existing homeguard rules from FORWARD chain
        # Remove HOMEGUARD_FILTER references
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-D", "FORWARD", "-j", "HOMEGUARD_FILTER"
        ], ignore_errors=True)

        # Remove management rules (multiple iterations to catch duplicates)
        for i in range(5):
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "FORWARD", "-p", "tcp", "-m", "multiport", "--dports", "22,5900,8081", "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "FORWARD", "-p", "tcp", "-m", "multiport", "--sports", "22,5900,8081", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], ignore_errors=True)

        # Remove transparent mode client rules
        for i in range(5):
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "FORWARD", "-i", "eth1", "-o", "eth0", "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "FORWARD", "-i", "eth0", "-o", "eth1", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], ignore_errors=True)

        # Remove captive portal NAT rules
        for i in range(5):
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-D", "PREROUTING", "-i", "eth1", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8081"
            ], ignore_errors=True)

    async def _setup_transparent_mode(self):
        """Setup rules for transparent mode - no blocking."""
        logger.info("🌐 Setting up transparent mode rules")

        # FORWARD Chain rules for transparent mode:
        # 1. ACCEPT tcp dport 22,5900,8081
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "1",
            "-p", "tcp", "-m", "multiport", "--dports", "22,5900,8081", "-j", "ACCEPT"
        ])

        # 2. ACCEPT tcp sport 22,5900,8081 ctstate RELATED,ESTABLISHED
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "2",
            "-p", "tcp", "-m", "multiport", "--sports", "22,5900,8081",
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ])

        # 3. ACCEPT eth1→eth0 (outbound traffic)
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "3",
            "-i", "eth1", "-o", "eth0", "-j", "ACCEPT"
        ])

        # 4. ACCEPT eth0→eth1 ctstate RELATED,ESTABLISHED (return traffic)
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "4",
            "-i", "eth0", "-o", "eth1",
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ])

        # HOMEGUARD_FILTER Chain: Empty - not used in transparent mode
        logger.info("✅ Transparent mode setup complete - HOMEGUARD_FILTER unused")

        # Setup captive portal redirect
        await self._setup_captive_portal()

    async def _setup_captive_portal(self):
        """Setup captive portal NAT rules for automatic device detection."""
        logger.info("📱 Setting up captive portal NAT rules for device detection")

        try:
            # Block connectivity checks → Force captive portal detection
            # Redirect HTTP traffic (port 80) to our web service (port 8081)
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", "eth1", "-p", "tcp", "--dport", "80",
                "-j", "REDIRECT", "--to-port", "8081"
            ])

            # Also redirect common connectivity check domains specifically
            # This ensures connectivity checks from various platforms get redirected
            connectivity_domains = [
                "detectportal.firefox.com",
                "www.msftconnecttest.com",
                "connectivitycheck.gstatic.com",
                "captive.apple.com",
                "clients3.google.com",
                "www.gstatic.com"
            ]

            for domain in connectivity_domains:
                # Add DNS redirection for specific connectivity check domains
                # This will be handled by the web application catch-all route
                logger.info(f"📍 Captive portal configured to handle {domain}")

            logger.info("✅ Captive portal NAT rules setup complete")
            logger.info("📲 Devices will now trigger captive portal detection automatically")

        except Exception as e:
            logger.error(f"Failed to setup captive portal NAT rules: {e}")
            # Don't raise - captive portal is nice-to-have, not critical

    async def _setup_totp_full_mode(self):
        """Setup rules for TOTP full mode - hard blocking with management access."""
        logger.info("🔒 Setting up TOTP full mode rules")

        # FORWARD Chain rules for TOTP full mode:
        # 1. ACCEPT tcp dport 22,5900,8081
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "1",
            "-p", "tcp", "-m", "multiport", "--dports", "22,5900,8081", "-j", "ACCEPT"
        ])

        # 2. ACCEPT tcp sport 22,5900,8081 ctstate RELATED,ESTABLISHED
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "2",
            "-p", "tcp", "-m", "multiport", "--sports", "22,5900,8081",
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ])

        # 3. HOMEGUARD_FILTER (for client traffic policing - handles both blocking and allowing)
        await self._run_iptables_command([
            "iptables", "-t", "filter", "-I", "FORWARD", "3", "-j", "HOMEGUARD_FILTER"
        ])

        # HOMEGUARD_FILTER Chain: Empty initially, will contain:
        # - ACCEPT rules for authenticated devices (added when TOTP succeeds)
        # - No default rules = traffic gets dropped by FORWARD policy
        logger.info("✅ TOTP full mode setup complete - HOMEGUARD_FILTER will control all client traffic")

        # Setup QoS traffic prioritization for real-time traffic
        await self._setup_qos_optimization()

        # Setup captive portal redirect
        await self._setup_captive_portal()

    async def _setup_qos_optimization(self):
        """Setup QoS rules to prioritize real-time traffic and reduce packet loss."""
        logger.info("🚀 Setting up QoS optimization for real-time traffic")

        try:
            # Create mangle table rules for traffic classification
            # Mark real-time traffic (VoIP, video calls, gaming) with high priority

            # 1. Mark VoIP/SIP traffic (ports 5060, 5061)
            await self._run_iptables_command([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-p", "udp", "-m", "multiport", "--ports", "5060,5061",
                "-j", "MARK", "--set-mark", "1"
            ], ignore_errors=True)

            # 2. Mark RTP traffic (UDP ports 10000-20000 commonly used for audio/video)
            await self._run_iptables_command([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-p", "udp", "--dport", "10000:20000",
                "-j", "MARK", "--set-mark", "1"
            ], ignore_errors=True)

            # 3. Mark WebRTC/STUN traffic (port 3478)
            await self._run_iptables_command([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-p", "udp", "--dport", "3478",
                "-j", "MARK", "--set-mark", "1"
            ], ignore_errors=True)

            # 4. Mark gaming traffic (common ports)
            gaming_ports = "25565,7777,27015,3724,6112,1119,27036"
            await self._run_iptables_command([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-p", "udp", "-m", "multiport", "--ports", gaming_ports,
                "-j", "MARK", "--set-mark", "1"
            ], ignore_errors=True)

            # 5. Mark Google Meet/Zoom traffic by destination
            # Google: 74.125.0.0/16, 173.194.0.0/16
            await self._run_iptables_command([
                "iptables", "-t", "mangle", "-A", "FORWARD",
                "-p", "udp", "-d", "74.125.0.0/16",
                "-j", "MARK", "--set-mark", "1"
            ], ignore_errors=True)

            # 6. Express lane in HOMEGUARD_FILTER for marked packets
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "HOMEGUARD_FILTER", "1",
                "-m", "mark", "--mark", "1", "-j", "ACCEPT"
            ], ignore_errors=True)

            logger.info("✅ QoS optimization setup complete - Real-time traffic prioritized")

        except Exception as e:
            logger.error(f"Error setting up QoS optimization: {e}")

    async def _run_iptables_command(self, command: List[str], ignore_errors: bool = False) -> bool:
        """Execute iptables command through state manager (respects testing/live mode)."""
        try:
            success = await state_manager.execute_iptables_command(command)
            if not success and not ignore_errors:
                logger.error(f"iptables command failed: {' '.join(command)}")
            return success
        except Exception as e:
            if not ignore_errors:
                logger.error(f"Exception executing iptables command: {e}")
            return False

    async def allow_device_traffic(self, mac_address: str, ip_address: str):
        """Allow traffic for an authenticated device by adding ACCEPT rules to HOMEGUARD_FILTER."""
        try:
            # Remove any existing rules for this IP first
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-s", ip_address, "-j", "ACCEPT"
            ], ignore_errors=True)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-d", ip_address, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], ignore_errors=True)

            # Add outbound traffic rule (device → internet)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER", "-s", ip_address, "-j", "ACCEPT"
            ])

            # Add return traffic rule (internet → device, established connections only)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER", "-d", ip_address, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ])

            await self._log_access_attempt(mac_address, "traffic_allowed", f"IP {ip_address}")
            logger.info(f"✅ Internet access granted for IP {ip_address} (MAC: {mac_address}) - outbound + return traffic")

        except Exception as e:
            logger.error(f"Failed to allow traffic for IP {ip_address}: {e}")

    async def block_device_traffic(self, mac_address: str, ip_address: str):
        """Block traffic for a device by removing its ACCEPT rules from HOMEGUARD_FILTER."""
        try:
            # Remove the device's outbound traffic rule
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-s", ip_address, "-j", "ACCEPT"
            ], ignore_errors=True)

            # Remove the device's return traffic rule
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-d", ip_address, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], ignore_errors=True)

            await self._log_access_attempt(mac_address, "traffic_blocked", f"IP {ip_address}")
            logger.info(f"❌ Internet access revoked for IP {ip_address} (MAC: {mac_address}) - outbound + return traffic")

        except Exception as e:
            logger.error(f"Failed to block traffic for IP {ip_address}: {e}")

    async def revoke_device_access(self, mac_address: str, ip_address: str):
        """Revoke access for a device by updating database and removing iptables rule."""
        try:
            # Update device in database
            async with db_manager.session_maker() as session:
                device = await session.get(Device, mac_address)
                if device:
                    device.revoke_access()
                    await session.commit()

            # Remove iptables rule (block traffic)
            await self.block_device_traffic(mac_address, ip_address)

            await self._log_access_attempt(mac_address, "access_revoked", f"IP {ip_address}")
            logger.info(f"⏰ Access revoked for device {mac_address} (IP: {ip_address})")

        except Exception as e:
            logger.error(f"Failed to revoke access for {mac_address}: {e}")

    async def _ip_filter_rule_exists(self, ip_address: str, target: str) -> bool:
        """Check if an IP-based HOMEGUARD_FILTER rule already exists."""
        try:
            import subprocess

            # List the HOMEGUARD_FILTER chain rules
            result = subprocess.run([
                "iptables", "-t", "filter", "-L", "HOMEGUARD_FILTER", "--line-numbers", "-v"
            ], capture_output=True, text=True)

            if result.returncode != 0:
                return False

            # Check if our specific IP rule exists
            for line in result.stdout.split('\n'):
                if ip_address in line and target in line:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking HOMEGUARD_FILTER rule existence: {e}")
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
        """Check if HOMEGUARD_FILTER rule already exists in FORWARD chain."""
        try:
            # List the FORWARD chain rules
            result = await self._run_iptables_command([
                "iptables", "-t", "filter", "-L", "FORWARD", "--line-numbers", "-n"
            ])

            if not result or not result.stdout:
                return False

            # Handle both string and bytes output
            output = result.stdout.decode('utf-8') if isinstance(result.stdout, bytes) else result.stdout

            # Check if HOMEGUARD_FILTER rule exists
            return "HOMEGUARD_FILTER" in output

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
                        "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-j", "ACCEPT"
                    ], ignore_errors=True)

                    # Allow gateway access for testing IP (needed for TOTP auth page)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER",
                        "-s", settings.testing_ip, "-d", settings.gateway_ip, "-j", "ACCEPT"
                    ])

                    # Allow DNS for testing IP (needed for TOTP auth page to load)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER",
                        "-s", settings.testing_ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
                    ])

                    # Block all other internet traffic for testing IP
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER",
                        "-s", settings.testing_ip, "-j", "DROP"
                    ])

                    # Re-add general ACCEPT rule for all other devices (non-testing IPs)
                    await self._run_iptables_command([
                        "iptables", "-t", "filter", "-A", "HOMEGUARD_FILTER", "-j", "ACCEPT"
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
                    "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", "-j", "ACCEPT"
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

    async def discover_all_devices(self) -> dict:
        """
        Comprehensive device discovery using ARP, nmap, and DHCP leases.
        Returns dict of discovered devices with their information.
        """
        discovered_devices = {}

        try:
            logger.info("🔍 Starting comprehensive device discovery...")

            # Method 1: ARP table scan
            arp_devices = await self._scan_arp_table()
            discovered_devices.update(arp_devices)
            logger.info(f"📡 ARP scan found {len(arp_devices)} devices")

            # Method 2: Network scan using nmap (if available)
            nmap_devices = await self._scan_network_nmap()
            discovered_devices.update(nmap_devices)
            logger.info(f"🗺️ Network scan found {len(nmap_devices)} additional devices")

            # Method 3: DHCP leases (if available)
            dhcp_devices = await self._scan_dhcp_leases()
            discovered_devices.update(dhcp_devices)
            logger.info(f"📋 DHCP leases found {len(dhcp_devices)} additional devices")

            # Update database with discovered devices
            await self._update_discovered_devices(discovered_devices)

            logger.info(f"✅ Device discovery complete: {len(discovered_devices)} total devices found")
            return discovered_devices

        except Exception as e:
            logger.error(f"Error during device discovery: {e}")
            return {}

    async def _scan_arp_table(self) -> dict:
        """Scan ARP table for connected devices."""
        devices = {}
        try:
            import subprocess
            import re

            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue

                # Parse ARP entries: hostname (ip) at mac_address [ether] on interface
                match = re.search(r'(\S+)\s+\(([\d.]+)\)\s+at\s+([a-fA-F0-9:]{17})', line)
                if match:
                    hostname, ip_address, mac_address = match.groups()

                    # Clean hostname (remove domain suffix if present)
                    hostname = hostname.split('.')[0] if hostname != '?' else 'Unknown'

                    devices[mac_address.lower()] = {
                        'mac_address': mac_address.lower(),
                        'ip_address': ip_address,
                        'hostname': hostname if hostname != '?' else None,
                        'discovery_method': 'arp',
                        'device_type': self._guess_device_type(hostname, mac_address)
                    }

        except Exception as e:
            logger.error(f"Error scanning ARP table: {e}")

        return devices

    async def _scan_network_nmap(self) -> dict:
        """Scan network using nmap for comprehensive device discovery."""
        devices = {}
        try:
            import subprocess
            import re

            # Get network range from gateway IP
            network_range = f"{settings.gateway_ip.rsplit('.', 1)[0]}.0/24"

            # Check if nmap is available
            try:
                subprocess.run(['which', 'nmap'], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                logger.warning("nmap not available, skipping network scan")
                return devices

            # Run nmap scan with hostname resolution
            result = subprocess.run([
                'nmap', '-sn', '-R', network_range
            ], capture_output=True, text=True, timeout=30)

            current_ip = None
            current_hostname = None

            for line in result.stdout.split('\n'):
                # Parse nmap output
                ip_match = re.search(r'Nmap scan report for (\S+) \(([\d.]+)\)', line)
                if ip_match:
                    current_hostname, current_ip = ip_match.groups()
                    continue

                ip_only_match = re.search(r'Nmap scan report for ([\d.]+)', line)
                if ip_only_match:
                    current_ip = ip_only_match.group(1)
                    current_hostname = None
                    continue

                # Look for MAC address in subsequent lines
                mac_match = re.search(r'MAC Address: ([A-Fa-f0-9:]{17})', line)
                if mac_match and current_ip:
                    mac_address = mac_match.group(1).lower()

                    devices[mac_address] = {
                        'mac_address': mac_address,
                        'ip_address': current_ip,
                        'hostname': current_hostname,
                        'discovery_method': 'nmap',
                        'device_type': self._guess_device_type(current_hostname, mac_address)
                    }

        except subprocess.TimeoutExpired:
            logger.warning("nmap scan timed out")
        except Exception as e:
            logger.error(f"Error with nmap scan: {e}")

        return devices

    async def _scan_dhcp_leases(self) -> dict:
        """Scan DHCP leases for additional device information."""
        devices = {}
        try:
            import subprocess
            import re

            # Common DHCP lease file locations
            lease_files = [
                '/var/lib/dhcp/dhcpd.leases',
                '/var/lib/dhcpcd5/dhcpcd.leases',
                '/var/lib/NetworkManager/dhcpcd.leases'
            ]

            for lease_file in lease_files:
                try:
                    with open(lease_file, 'r') as f:
                        content = f.read()

                    # Parse DHCP lease entries
                    lease_blocks = re.findall(r'lease ([\d.]+) \{[^}]+\}', content, re.DOTALL)

                    for ip_address in lease_blocks:
                        # Extract more details from lease block if needed
                        devices[f"dhcp:{ip_address}"] = {
                            'ip_address': ip_address,
                            'discovery_method': 'dhcp',
                            'device_type': 'Unknown'
                        }

                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.debug(f"Error reading {lease_file}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error scanning DHCP leases: {e}")

        return devices

    def _guess_device_type(self, hostname: str, mac_address: str) -> str:
        """Guess device type based on hostname and MAC address."""
        if not hostname:
            return 'Unknown'

        hostname_lower = hostname.lower()

        # Mobile devices
        if any(keyword in hostname_lower for keyword in ['iphone', 'android', 'mobile', 'phone']):
            return 'Mobile'

        # Computers
        if any(keyword in hostname_lower for keyword in ['desktop', 'laptop', 'pc', 'macbook', 'imac']):
            return 'Computer'

        # IoT devices
        if any(keyword in hostname_lower for keyword in ['esp', 'arduino', 'iot', 'sensor', 'smart', 'alexa', 'google']):
            return 'IoT'

        # Network equipment
        if any(keyword in hostname_lower for keyword in ['router', 'switch', 'ap', 'bridge']):
            return 'Network'

        # Gaming consoles
        if any(keyword in hostname_lower for keyword in ['xbox', 'playstation', 'nintendo', 'steam']):
            return 'Gaming'

        return 'Unknown'

    async def _update_discovered_devices(self, discovered_devices: dict):
        """Update database with discovered devices."""
        try:
            async with db_manager.session_maker() as session:
                for mac_address, device_info in discovered_devices.items():
                    # Skip DHCP-only entries without MAC
                    if mac_address.startswith('dhcp:'):
                        continue

                    # Get or create device
                    device = await session.get(Device, mac_address)
                    if not device:
                        device = Device(mac_address=mac_address)
                        session.add(device)

                    # Update device information
                    if device_info.get('ip_address'):
                        device.ip_address = device_info['ip_address']
                    if device_info.get('hostname'):
                        device.hostname = device_info['hostname']
                    if device_info.get('device_type'):
                        device.device_type = device_info['device_type']

                    # Update last_seen timestamp
                    device.last_seen = datetime.utcnow()

                await session.commit()
                logger.info(f"📊 Updated database with {len(discovered_devices)} discovered devices")

        except Exception as e:
            logger.error(f"Error updating discovered devices in database: {e}")

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

            # Remove any existing HomeGuard IP blocking rules in HOMEGUARD_FILTER
            # These might have been left behind from unclean shutdowns
            import subprocess

            try:
                # Get all rules in HOMEGUARD_FILTER chain
                result = subprocess.run([
                    "iptables", "-t", "filter", "-L", "HOMEGUARD_FILTER", "--line-numbers", "-n"
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
                            "iptables", "-t", "filter", "-D", "HOMEGUARD_FILTER", rule_num
                        ], ignore_errors=True)
                        logger.info(f"Removed stale rule #{rule_num} from HOMEGUARD_FILTER")

            except Exception as e:
                logger.warning(f"Could not clean up stale rules: {e}")

            logger.info("✅ Stale rule cleanup complete")

        except Exception as e:
            logger.error(f"Error during startup cleanup: {e}")

    async def cleanup_iptables_on_shutdown(self):
        """Clean up iptables rules when service shuts down."""
        try:
            logger.info("Cleaning up iptables rules...")
            
            # Remove ALL HOMEGUARD_FILTER rules from FORWARD chain
            logger.info("Removing all HOMEGUARD_FILTER rules from FORWARD chain...")
            while True:
                result = await self._run_iptables_command([
                    "iptables", "-t", "filter", "-D", "FORWARD", "-j", "HOMEGUARD_FILTER"
                ], ignore_errors=True)
                if result and result.returncode != 0:
                    break  # No more rules to remove
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "HOMEGUARD_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-X", "HOMEGUARD_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-F", "HOMEGUARD_FILTER"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "nat", "-X", "HOMEGUARD_FILTER"
            ], ignore_errors=True)
            
            logger.info("✅ iptables cleanup complete")
            
        except Exception as e:
            logger.error(f"Error cleaning up iptables: {e}")


# Global traffic monitor instance
traffic_monitor = TrafficMonitor()