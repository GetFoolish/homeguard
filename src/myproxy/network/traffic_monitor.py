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
            client_ip = self._get_client_ip_from_mac(mac_address)
            if client_ip:
                await self.allow_device_traffic(mac_address, client_ip)
            else:
                logger.warning(f"Could not determine IP for MAC {mac_address}, traffic filtering may not work")
            
            await self._log_access_attempt(mac_address, "auth_success", f"Granted {duration_key} access")
            
            duration_text = duration_key.replace('_', ' ')
            return True, f"Access granted for {duration_text}"
            
        except Exception as e:
            logger.error(f"Authentication error for device {mac_address}: {e}")
            return False, "Authentication system error"
    
    async def revoke_device_access(self, mac_address: str) -> bool:
        """
        Revoke access for a specific device.
        
        Args:
            mac_address: Device MAC address to revoke access for
            
        Returns:
            bool: True if successfully revoked, False otherwise
        """
        try:
            # Remove from authorized devices set
            self.authorized_devices.discard(mac_address)
            
            # Update connected device status
            if mac_address in self.connected_devices:
                self.connected_devices[mac_address].is_authorized = False
            
            # Block traffic for this device
            client_ip = self._get_client_ip_from_mac(mac_address)
            if client_ip:
                await self.block_device_traffic(mac_address, client_ip)
            
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
            
            # Redirect all client traffic through our filter chain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "FORWARD", "1", "-j", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            # Allow loopback and established connections
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1", 
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ])
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "2",
                "-i", "lo", "-j", "ACCEPT"
            ])
            
            logger.info("✅ iptables traffic filtering setup complete")
            
        except Exception as e:
            logger.error(f"Failed to setup iptables traffic filtering: {e}")
            raise

    async def allow_device_traffic(self, mac_address: str, ip_address: str):
        """Allow traffic for an authenticated device using iptables ACCEPT rule."""
        try:
            # Remove any existing block rules for this device first
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER",
                "-s", ip_address, "-j", "DROP"
            ], ignore_errors=True)
            
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER", 
                "-m", "mac", "--mac-source", mac_address, "-j", "DROP"
            ], ignore_errors=True)
            
            # Add ACCEPT rule for this device (by IP and MAC)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "3",
                "-s", ip_address, "-m", "mac", "--mac-source", mac_address, "-j", "ACCEPT"
            ])
            
            await self._log_access_attempt(mac_address, "traffic_allowed", f"IP {ip_address}")
            logger.info(f"✅ Traffic access granted for device {mac_address} ({ip_address})")
            
        except Exception as e:
            logger.error(f"Failed to allow traffic for device {mac_address}: {e}")

    async def block_device_traffic(self, mac_address: str, ip_address: str):
        """Block traffic for a device using iptables DROP rule."""
        try:
            # Remove any existing allow rules for this device first
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "MYPROXY_FILTER",
                "-s", ip_address, "-m", "mac", "--mac-source", mac_address, "-j", "ACCEPT"
            ], ignore_errors=True)
            
            # Add DROP rule for this device (by IP and MAC)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "3",
                "-s", ip_address, "-m", "mac", "--mac-source", mac_address, "-j", "DROP"
            ])
            
            await self._log_access_attempt(mac_address, "traffic_blocked", f"IP {ip_address}")
            logger.info(f"❌ Traffic blocked for device {mac_address} ({ip_address})")
            
        except Exception as e:
            logger.error(f"Failed to block traffic for device {mac_address}: {e}")

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

    async def cleanup_iptables_on_shutdown(self):
        """Clean up iptables rules when service shuts down."""
        try:
            logger.info("Cleaning up iptables rules...")
            
            # Remove our custom chains and rules
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-D", "FORWARD", "-j", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
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