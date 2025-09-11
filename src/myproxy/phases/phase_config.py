"""Phase configuration management for MyProxy rollout system."""

import json
import os
import logging
from enum import IntEnum
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class Phase(IntEnum):
    """Phase definitions for gradual rollout."""
    TRANSPARENT_BRIDGE = 1
    TRAFFIC_MONITORING = 2
    BLOCK_NDTV = 3
    BLOCK_KEYWORDS = 4
    GOOGLE_SHEETS = 5
    FULL_TOTP = 6


@dataclass
class PhaseRule:
    """Individual filtering rule for a phase."""
    rule_type: str  # 'domain', 'keyword', 'url_pattern', 'totp_required'
    pattern: str    # The pattern to match
    action: str     # 'block', 'allow', 'log_only'
    enabled: bool = True
    description: str = ""


@dataclass
class PhaseConfiguration:
    """Configuration for a specific phase."""
    phase: int
    name: str
    description: str
    rules: List[PhaseRule]
    iptables_policy: str = "ACCEPT"  # ACCEPT, DROP, or CUSTOM
    totp_required: bool = False
    logging_enabled: bool = True
    

class PhaseConfig:
    """Manages phase configuration and persistence."""
    
    def __init__(self, config_dir: str = "/etc/myproxy"):
        """Initialize phase configuration manager."""
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "phase.conf"
        self.rules_file = self.config_dir / "phase_rules.json"
        self.current_phase = Phase.TRANSPARENT_BRIDGE
        self.phase_configs: Dict[int, PhaseConfiguration] = {}
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize default phase configurations
        self._initialize_default_phases()
        
        # Load current configuration
        self.load_configuration()
    
    def _initialize_default_phases(self):
        """Initialize default phase configurations."""
        
        # Phase 1: Transparent Bridge
        self.phase_configs[Phase.TRANSPARENT_BRIDGE] = PhaseConfiguration(
            phase=Phase.TRANSPARENT_BRIDGE,
            name="Transparent Bridge",
            description="Pass all traffic through without filtering - verify connectivity",
            rules=[],
            iptables_policy="ACCEPT",
            totp_required=False,
            logging_enabled=True
        )
        
        # Phase 2: Traffic Monitoring
        self.phase_configs[Phase.TRAFFIC_MONITORING] = PhaseConfiguration(
            phase=Phase.TRAFFIC_MONITORING,
            name="Traffic Monitoring",
            description="Log all traffic patterns but allow everything",
            rules=[
                PhaseRule("monitor", "*", "log_only", True, "Log all traffic for analysis")
            ],
            iptables_policy="ACCEPT",
            totp_required=False,
            logging_enabled=True
        )
        
        # Phase 3: Block NDTV.com
        self.phase_configs[Phase.BLOCK_NDTV] = PhaseConfiguration(
            phase=Phase.BLOCK_NDTV,
            name="Block NDTV.com",
            description="Block NDTV.com domain only - test specific domain blocking",
            rules=[
                PhaseRule("domain", "ndtv.com", "block", True, "Block NDTV.com domain"),
                PhaseRule("domain", "*.ndtv.com", "block", True, "Block NDTV.com subdomains"),
                PhaseRule("url_pattern", r".*ndtv\.com.*", "block", True, "Block URLs containing ndtv.com")
            ],
            iptables_policy="ACCEPT",
            totp_required=False,
            logging_enabled=True
        )
        
        # Phase 4: Block Keywords
        self.phase_configs[Phase.BLOCK_KEYWORDS] = PhaseConfiguration(
            phase=Phase.BLOCK_KEYWORDS,
            name="Block Keywords",
            description="Block content containing mickey and jj keywords",
            rules=[
                PhaseRule("domain", "ndtv.com", "block", True, "Block NDTV.com domain"),
                PhaseRule("domain", "*.ndtv.com", "block", True, "Block NDTV.com subdomains"),
                PhaseRule("keyword", "mickey", "block", True, "Block content containing 'mickey'"),
                PhaseRule("keyword", "jj", "block", True, "Block content containing 'jj'"),
                PhaseRule("keyword", "mickey and jj", "block", True, "Block content containing 'mickey and jj'")
            ],
            iptables_policy="ACCEPT",
            totp_required=False,
            logging_enabled=True
        )
        
        # Phase 5: Google Sheets Integration
        self.phase_configs[Phase.GOOGLE_SHEETS] = PhaseConfiguration(
            phase=Phase.GOOGLE_SHEETS,
            name="Google Sheets Integration",
            description="Dynamic rule management via Google Sheets",
            rules=[
                PhaseRule("domain", "ndtv.com", "block", True, "Block NDTV.com domain"),
                PhaseRule("keyword", "mickey", "block", True, "Block content containing 'mickey'"),
                PhaseRule("keyword", "jj", "block", True, "Block content containing 'jj'"),
                PhaseRule("sheets_sync", "auto", "sync", True, "Sync rules from Google Sheets")
            ],
            iptables_policy="ACCEPT",
            totp_required=False,
            logging_enabled=True
        )
        
        # Phase 6: Full TOTP Authentication
        self.phase_configs[Phase.FULL_TOTP] = PhaseConfiguration(
            phase=Phase.FULL_TOTP,
            name="Full TOTP Authentication",
            description="Complete security implementation with all features",
            rules=[
                PhaseRule("totp_required", "*", "require_auth", True, "Require TOTP authentication"),
                PhaseRule("domain", "ndtv.com", "block", True, "Block NDTV.com domain"),
                PhaseRule("keyword", "mickey", "block", True, "Block content containing 'mickey'"),
                PhaseRule("keyword", "jj", "block", True, "Block content containing 'jj'"),
                PhaseRule("sheets_sync", "auto", "sync", True, "Sync rules from Google Sheets")
            ],
            iptables_policy="DROP",  # Default drop, allow only authenticated
            totp_required=True,
            logging_enabled=True
        )
    
    def get_current_phase(self) -> int:
        """Get the current active phase."""
        return self.current_phase
    
    def get_phase_config(self, phase: int) -> Optional[PhaseConfiguration]:
        """Get configuration for a specific phase."""
        return self.phase_configs.get(phase)
    
    def get_current_phase_config(self) -> PhaseConfiguration:
        """Get configuration for the current active phase."""
        return self.phase_configs[self.current_phase]
    
    def set_phase(self, phase: int) -> bool:
        """Set the current active phase."""
        if phase not in self.phase_configs:
            logger.error(f"Invalid phase: {phase}")
            return False
        
        old_phase = self.current_phase
        self.current_phase = phase
        
        # Save configuration
        if self.save_configuration():
            logger.info(f"Phase changed from {old_phase} to {phase}")
            return True
        else:
            # Rollback on save failure
            self.current_phase = old_phase
            logger.error(f"Failed to save phase change to {phase}")
            return False
    
    def get_phase_rules(self, phase: Optional[int] = None) -> List[PhaseRule]:
        """Get rules for a specific phase (or current phase)."""
        phase = phase or self.current_phase
        config = self.phase_configs.get(phase)
        return config.rules if config else []
    
    def add_rule_to_phase(self, phase: int, rule: PhaseRule) -> bool:
        """Add a rule to a specific phase."""
        if phase not in self.phase_configs:
            logger.error(f"Invalid phase: {phase}")
            return False
        
        self.phase_configs[phase].rules.append(rule)
        return self.save_rules()
    
    def remove_rule_from_phase(self, phase: int, rule_pattern: str) -> bool:
        """Remove a rule from a specific phase."""
        if phase not in self.phase_configs:
            logger.error(f"Invalid phase: {phase}")
            return False
        
        config = self.phase_configs[phase]
        config.rules = [r for r in config.rules if r.pattern != rule_pattern]
        return self.save_rules()
    
    def load_configuration(self):
        """Load phase configuration from file."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    content = f.read().strip()
                    if content.startswith('PHASE='):
                        phase_str = content.split('=')[1].strip()
                        self.current_phase = int(phase_str)
                        logger.info(f"Loaded current phase: {self.current_phase}")
                    else:
                        # Try to parse as JSON for future compatibility
                        config_data = json.loads(content)
                        self.current_phase = config_data.get('current_phase', Phase.TRANSPARENT_BRIDGE)
            else:
                logger.info("No existing phase configuration found, starting with Phase 1")
                
            # Load custom rules if they exist
            self.load_rules()
            
        except Exception as e:
            logger.error(f"Error loading phase configuration: {e}")
            logger.info("Using default Phase 1 configuration")
            self.current_phase = Phase.TRANSPARENT_BRIDGE
    
    def save_configuration(self) -> bool:
        """Save current phase configuration to file."""
        try:
            # Simple format for easy shell scripting
            with open(self.config_file, 'w') as f:
                f.write(f"PHASE={self.current_phase}\n")
            
            # Also save as JSON for detailed configuration
            config_data = {
                'current_phase': self.current_phase,
                'phase_name': self.phase_configs[self.current_phase].name,
                'timestamp': str(Path(__file__).stat().st_mtime)
            }
            
            json_file = self.config_dir / "phase_status.json"
            with open(json_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Phase configuration saved: Phase {self.current_phase}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving phase configuration: {e}")
            return False
    
    def load_rules(self):
        """Load custom rules from file."""
        try:
            if self.rules_file.exists():
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)
                
                # Apply custom rules to phases
                for phase_str, rules_list in rules_data.items():
                    phase = int(phase_str)
                    if phase in self.phase_configs:
                        # Replace default rules with custom ones
                        self.phase_configs[phase].rules = [
                            PhaseRule(**rule_data) for rule_data in rules_list
                        ]
                
                logger.info("Custom phase rules loaded successfully")
                
        except Exception as e:
            logger.error(f"Error loading custom rules: {e}")
            logger.info("Using default phase rules")
    
    def save_rules(self) -> bool:
        """Save custom rules to file."""
        try:
            rules_data = {}
            for phase, config in self.phase_configs.items():
                rules_data[str(phase)] = [asdict(rule) for rule in config.rules]
            
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            logger.info("Phase rules saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving phase rules: {e}")
            return False
    
    def validate_phase_transition(self, from_phase: int, to_phase: int) -> tuple[bool, str]:
        """Validate if phase transition is safe."""
        if to_phase == from_phase:
            return True, "No change needed"
        
        if to_phase not in self.phase_configs:
            return False, f"Invalid target phase: {to_phase}"
        
        # Allow any phase transition (for testing flexibility)
        # In production, you might want to restrict certain transitions
        if to_phase < from_phase:
            logger.warning(f"Rolling back from Phase {from_phase} to Phase {to_phase}")
        
        return True, f"Transition from Phase {from_phase} to Phase {to_phase} is valid"
    
    def get_phase_summary(self) -> Dict[str, Any]:
        """Get summary of all phases and current status."""
        return {
            'current_phase': self.current_phase,
            'current_phase_name': self.phase_configs[self.current_phase].name,
            'current_phase_description': self.phase_configs[self.current_phase].description,
            'available_phases': {
                phase: {
                    'name': config.name,
                    'description': config.description,
                    'rules_count': len(config.rules),
                    'totp_required': config.totp_required
                }
                for phase, config in self.phase_configs.items()
            }
        }