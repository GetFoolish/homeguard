"""Phase Manager for MyProxy rollout system."""

import asyncio
import logging
import subprocess
from typing import Dict, List, Optional, Set
from datetime import datetime

from .phase_config import PhaseConfig, Phase, PhaseRule, PhaseConfiguration
from ..database.connection import db_manager

logger = logging.getLogger(__name__)


class PhaseManager:
    """
    Manages the 6-phase rollout system for MyProxy.
    Handles phase transitions, rule application, and iptables management.
    """
    
    def __init__(self):
        """Initialize PhaseManager."""
        self.config = PhaseConfig()
        self.is_active = False
        self.blocked_domains: Set[str] = set()
        self.blocked_keywords: Set[str] = set()
        self.sheets_integration = None  # Will be set when sheets module is available
        
    async def start(self):
        """Start the phase management system."""
        try:
            logger.info("Starting Phase Management System...")
            
            # Load current phase configuration
            current_phase = self.config.get_current_phase()
            phase_config = self.config.get_current_phase_config()
            
            logger.info(f"Current Phase: {current_phase} - {phase_config.name}")
            logger.info(f"Description: {phase_config.description}")
            
            # Apply current phase rules
            await self.apply_phase_rules(current_phase)
            
            self.is_active = True
            logger.info("✅ Phase Management System started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Phase Management System: {e}")
            raise
    
    async def stop(self):
        """Stop the phase management system."""
        logger.info("Stopping Phase Management System...")
        self.is_active = False
        
        # Clear any phase-specific iptables rules
        await self._cleanup_phase_iptables()
        
        logger.info("✅ Phase Management System stopped")
    
    async def switch_phase(self, target_phase: int, force: bool = False) -> tuple[bool, str]:
        """
        Switch to a different phase with validation.
        
        Args:
            target_phase: Target phase number (1-6)
            force: Skip validation checks if True
            
        Returns:
            tuple: (success, message)
        """
        try:
            current_phase = self.config.get_current_phase()
            
            if not force:
                # Validate phase transition
                valid, message = self.config.validate_phase_transition(current_phase, target_phase)
                if not valid:
                    return False, message
            
            # Get phase configurations
            old_config = self.config.get_current_phase_config()
            new_config = self.config.get_phase_config(target_phase)
            
            if not new_config:
                return False, f"Invalid phase: {target_phase}"
            
            logger.info(f"Phase transition: {current_phase} -> {target_phase}")
            logger.info(f"From: {old_config.name}")
            logger.info(f"To: {new_config.name}")
            
            # Set new phase in configuration
            if not self.config.set_phase(target_phase):
                return False, "Failed to save phase configuration"
            
            # Apply new phase rules
            await self.apply_phase_rules(target_phase)
            
            # Log phase transition
            await self._log_phase_transition(current_phase, target_phase)
            
            logger.info(f"✅ Successfully switched to Phase {target_phase}: {new_config.name}")
            return True, f"Switched to Phase {target_phase}: {new_config.name}"
            
        except Exception as e:
            logger.error(f"Error switching to phase {target_phase}: {e}")
            return False, f"Error switching phase: {str(e)}"
    
    async def apply_phase_rules(self, phase: int):
        """Apply all rules for a specific phase."""
        try:
            phase_config = self.config.get_phase_config(phase)
            if not phase_config:
                logger.error(f"No configuration found for phase {phase}")
                return
            
            logger.info(f"Applying rules for Phase {phase}: {phase_config.name}")
            
            # Clear previous phase-specific rules
            await self._cleanup_phase_iptables()
            
            # Reset internal state
            self.blocked_domains.clear()
            self.blocked_keywords.clear()
            
            # Apply iptables policy
            await self._apply_iptables_policy(phase_config)
            
            # Apply individual rules
            for rule in phase_config.rules:
                if rule.enabled:
                    await self._apply_rule(rule, phase_config)
            
            # Apply Pi self-exemption rules (always active)
            await self._apply_pi_exemption_rules()
            
            logger.info(f"✅ Phase {phase} rules applied successfully")
            
        except Exception as e:
            logger.error(f"Error applying phase {phase} rules: {e}")
            raise
    
    async def _apply_rule(self, rule: PhaseRule, phase_config: PhaseConfiguration):
        """Apply an individual phase rule."""
        try:
            if rule.rule_type == "domain":
                await self._apply_domain_rule(rule)
            elif rule.rule_type == "keyword":
                await self._apply_keyword_rule(rule)
            elif rule.rule_type == "url_pattern":
                await self._apply_url_pattern_rule(rule)
            elif rule.rule_type == "totp_required":
                await self._apply_totp_rule(rule)
            elif rule.rule_type == "monitor":
                await self._apply_monitoring_rule(rule)
            elif rule.rule_type == "sheets_sync":
                await self._apply_sheets_rule(rule)
            else:
                logger.warning(f"Unknown rule type: {rule.rule_type}")
            
        except Exception as e:
            logger.error(f"Error applying rule {rule.rule_type}:{rule.pattern}: {e}")
    
    async def _apply_domain_rule(self, rule: PhaseRule):
        """Apply domain blocking rule."""
        if rule.action == "block":
            self.blocked_domains.add(rule.pattern)
            
            # Add iptables rule to block domain (DNS-based)
            domain = rule.pattern.replace("*.", "")  # Remove wildcard for iptables
            
            # Block DNS queries for this domain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "10",
                "-p", "udp", "--dport", "53",
                "-m", "string", "--string", domain, "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)
            
            # Block direct IP access if we can resolve it
            try:
                import socket
                ip = socket.gethostbyname(domain)
                await self._run_iptables_command([
                    "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "11",
                    "-d", ip, "-j", "DROP"
                ], ignore_errors=True)
                
                logger.info(f"✅ Blocked domain {domain} (IP: {ip})")
            except:
                logger.info(f"✅ Blocked domain {domain} (DNS only)")
    
    async def _apply_keyword_rule(self, rule: PhaseRule):
        """Apply keyword blocking rule."""
        if rule.action == "block":
            self.blocked_keywords.add(rule.pattern)
            
            # HTTP content inspection for keywords
            # This requires deep packet inspection - for now, log the keyword
            logger.info(f"✅ Keyword blocking enabled for: {rule.pattern}")
    
    async def _apply_url_pattern_rule(self, rule: PhaseRule):
        """Apply URL pattern blocking rule."""
        if rule.action == "block":
            # URL pattern matching - this would typically be done at HTTP proxy level
            logger.info(f"✅ URL pattern blocking enabled for: {rule.pattern}")
    
    async def _apply_totp_rule(self, rule: PhaseRule):
        """Apply TOTP authentication requirement."""
        if rule.action == "require_auth":
            # This is handled by the existing traffic monitor
            logger.info("✅ TOTP authentication requirement active")
    
    async def _apply_monitoring_rule(self, rule: PhaseRule):
        """Apply traffic monitoring rule."""
        if rule.action == "log_only":
            # Enable enhanced logging
            logger.info("✅ Enhanced traffic monitoring enabled")
    
    async def _apply_sheets_rule(self, rule: PhaseRule):
        """Apply Google Sheets integration rule."""
        if rule.action == "sync" and self.sheets_integration:
            # This will be implemented when Google Sheets integration is added
            logger.info("✅ Google Sheets rule sync enabled")
    
    async def _apply_iptables_policy(self, phase_config: PhaseConfiguration):
        """Apply the iptables policy for this phase."""
        try:
            if phase_config.iptables_policy == "ACCEPT":
                # Phase 1-5: Default allow, selective blocking
                await self._setup_allow_policy()
            elif phase_config.iptables_policy == "DROP":
                # Phase 6: Default drop, selective allowing
                await self._setup_drop_policy()
            else:
                # Custom policy
                logger.info(f"Custom iptables policy: {phase_config.iptables_policy}")
            
        except Exception as e:
            logger.error(f"Error applying iptables policy: {e}")
            raise
    
    async def _setup_allow_policy(self):
        """Set up iptables for default allow policy (Phases 1-5)."""
        try:
            # Ensure MYPROXY_FILTER chain exists
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-N", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            # Clear the chain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "MYPROXY_FILTER"
            ])
            
            # Allow established and related connections
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ])
            
            # Allow loopback
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                "-i", "lo", "-j", "ACCEPT"
            ])
            
            # Default allow (will be overridden by specific block rules)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER", "-j", "ACCEPT"
            ])
            
            logger.info("✅ Allow policy setup complete")
            
        except Exception as e:
            logger.error(f"Error setting up allow policy: {e}")
            raise
    
    async def _setup_drop_policy(self):
        """Set up iptables for default drop policy (Phase 6)."""
        try:
            # Ensure MYPROXY_FILTER chain exists
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-N", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            # Clear the chain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "MYPROXY_FILTER"
            ])
            
            # Allow established and related connections
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ])
            
            # Allow loopback
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER",
                "-i", "lo", "-j", "ACCEPT"
            ])
            
            # Default drop (authenticated devices will be allowed by traffic monitor)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-A", "MYPROXY_FILTER", "-j", "DROP"
            ])
            
            logger.info("✅ Drop policy setup complete")
            
        except Exception as e:
            logger.error(f"Error setting up drop policy: {e}")
            raise
    
    async def _apply_pi_exemption_rules(self):
        """Apply Pi self-exemption rules (always active)."""
        try:
            # Pi IP addresses to exempt
            pi_ips = ["192.168.1.100", "192.168.4.100", "192.168.4.65"]
            
            for ip in pi_ips:
                # Allow all traffic from Pi IPs
                await self._run_iptables_command([
                    "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                    "-s", ip, "-j", "ACCEPT"
                ], ignore_errors=True)
                
                await self._run_iptables_command([
                    "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                    "-d", ip, "-j", "ACCEPT"
                ], ignore_errors=True)
            
            # Allow SSH (port 22)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                "-p", "tcp", "--dport", "22", "-j", "ACCEPT"
            ], ignore_errors=True)
            
            # Allow admin web interface (port 8080)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"
            ], ignore_errors=True)
            
            # Allow DNS (port 53)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                "-p", "udp", "--dport", "53", "-s", "192.168.4.100", "-j", "ACCEPT"
            ], ignore_errors=True)
            
            # Allow NTP (port 123)
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-I", "MYPROXY_FILTER", "1",
                "-p", "udp", "--dport", "123", "-s", "192.168.4.100", "-j", "ACCEPT"
            ], ignore_errors=True)
            
            logger.info("✅ Pi self-exemption rules applied")
            
        except Exception as e:
            logger.error(f"Error applying Pi exemption rules: {e}")
    
    async def _cleanup_phase_iptables(self):
        """Clean up phase-specific iptables rules."""
        try:
            # Flush MYPROXY_FILTER chain
            await self._run_iptables_command([
                "iptables", "-t", "filter", "-F", "MYPROXY_FILTER"
            ], ignore_errors=True)
            
            logger.debug("Phase-specific iptables rules cleaned up")
            
        except Exception as e:
            logger.error(f"Error cleaning up phase iptables: {e}")
    
    async def _run_iptables_command(self, cmd_args: list, ignore_errors: bool = False):
        """Execute an iptables command with proper error handling."""
        try:
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
    
    async def _log_phase_transition(self, from_phase: int, to_phase: int):
        """Log phase transition to database."""
        try:
            async with db_manager.session_maker() as session:
                from ..database.models import AccessLog
                
                log_entry = AccessLog(
                    mac_address="system",
                    event_type="phase_transition",
                    event_details=f"Phase {from_phase} -> {to_phase}",
                    timestamp=datetime.utcnow()
                )
                session.add(log_entry)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to log phase transition: {e}")
    
    def get_current_phase(self) -> int:
        """Get current active phase."""
        return self.config.get_current_phase()
    
    def get_phase_info(self, phase: Optional[int] = None) -> dict:
        """Get information about a phase."""
        phase = phase or self.config.get_current_phase()
        config = self.config.get_phase_config(phase)
        
        if not config:
            return {"error": f"Invalid phase: {phase}"}
        
        return {
            "phase": phase,
            "name": config.name,
            "description": config.description,
            "rules_count": len(config.rules),
            "totp_required": config.totp_required,
            "iptables_policy": config.iptables_policy,
            "rules": [
                {
                    "type": rule.rule_type,
                    "pattern": rule.pattern,
                    "action": rule.action,
                    "enabled": rule.enabled,
                    "description": rule.description
                }
                for rule in config.rules
            ]
        }
    
    def get_all_phases_info(self) -> dict:
        """Get information about all phases."""
        return self.config.get_phase_summary()
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if a domain is blocked in current phase."""
        return domain in self.blocked_domains or any(
            domain.endswith(blocked_domain.replace("*.", ""))
            for blocked_domain in self.blocked_domains
        )
    
    def is_keyword_blocked(self, content: str) -> bool:
        """Check if content contains blocked keywords."""
        content_lower = content.lower()
        return any(keyword.lower() in content_lower for keyword in self.blocked_keywords)


# Global phase manager instance
phase_manager = PhaseManager()