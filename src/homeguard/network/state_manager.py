"""
State manager for iptables rules - handles both testing and live modes.
"""

import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from ..config.settings import settings

logger = logging.getLogger(__name__)

class IptablesStateManager:
    """Manages desired vs actual iptables state with testing/live modes."""

    def __init__(self):
        self.state_dir = Path("/tmp/homeguard_state")
        self.state_dir.mkdir(exist_ok=True)
        self.desired_state_file = self.state_dir / "desired_rules.json"
        self.actual_state_file = self.state_dir / "actual_rules.json"
        self.drift_log_file = self.state_dir / "drift_log.json"

    async def set_desired_rule(self, chain: str, position: int, rule: Dict[str, Any]):
        """Set a desired rule in the state."""
        desired_state = await self._load_desired_state()

        if chain not in desired_state:
            desired_state[chain] = {}

        desired_state[chain][str(position)] = {
            "rule": rule,
            "timestamp": datetime.utcnow().isoformat(),
            "mode": settings.gateway_mode
        }

        await self._save_desired_state(desired_state)

        if settings.execution_mode == "testing":
            logger.info(f"🧪 TESTING MODE: Would add rule to {chain}:{position}")
            logger.info(f"🧪 Rule: {rule}")
        else:
            logger.info(f"📝 Desired state updated: {chain}:{position}")

    async def clear_desired_chain(self, chain: str):
        """Clear all desired rules for a chain."""
        desired_state = await self._load_desired_state()
        desired_state[chain] = {}
        await self._save_desired_state(desired_state)

        if settings.execution_mode == "testing":
            logger.info(f"🧪 TESTING MODE: Would clear chain {chain}")
        else:
            logger.info(f"📝 Desired state: cleared {chain}")

    async def execute_iptables_command(self, command: List[str]) -> bool:
        """Execute iptables command respecting execution mode."""
        if settings.execution_mode == "testing":
            # Testing mode: log command but don't execute
            logger.info(f"🧪 TESTING MODE: {' '.join(command)}")
            await self._log_testing_command(command)
            return True
        else:
            # Live mode: execute command
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    logger.debug(f"✅ Executed: {' '.join(command)}")
                    return True
                else:
                    logger.error(f"❌ Command failed: {' '.join(command)}")
                    logger.error(f"❌ Error: {stderr.decode()}")
                    return False

            except Exception as e:
                logger.error(f"❌ Exception executing command: {e}")
                return False

    async def monitor_drift(self):
        """Monitor drift between desired and actual state (live mode only)."""
        if settings.execution_mode != "live":
            return

        logger.info("🔍 Starting drift monitoring...")

        while True:
            try:
                await self._check_drift()
                await asyncio.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in drift monitoring: {e}")
                await asyncio.sleep(60)  # Retry in 1 minute on error

    async def _check_drift(self):
        """Check for drift between desired and actual state."""
        desired_state = await self._load_desired_state()
        actual_state = await self._capture_actual_state()

        drifts = []

        for chain, rules in desired_state.items():
            if chain not in actual_state:
                drifts.append(f"Missing chain: {chain}")
                continue

            for position, rule_info in rules.items():
                if position not in actual_state[chain]:
                    drifts.append(f"Missing rule: {chain}:{position}")
                elif actual_state[chain][position] != rule_info["rule"]:
                    drifts.append(f"Rule mismatch: {chain}:{position}")

        if drifts:
            await self._log_drift(drifts)
            logger.warning(f"🚨 Detected {len(drifts)} drift(s): {drifts}")
            # TODO: Implement auto-correction
        else:
            logger.debug("✅ No drift detected")

    async def _load_desired_state(self) -> Dict:
        """Load desired state from JSON file."""
        try:
            if self.desired_state_file.exists():
                with open(self.desired_state_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading desired state: {e}")

        return {}

    async def _save_desired_state(self, state: Dict):
        """Save desired state to JSON file."""
        try:
            with open(self.desired_state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving desired state: {e}")

    async def _capture_actual_state(self) -> Dict:
        """Capture actual iptables state."""
        # This would parse actual iptables rules
        # For now, return empty state as placeholder
        return {}

    async def _log_testing_command(self, command: List[str]):
        """Log command for testing mode analysis."""
        testing_log = self.state_dir / "testing_commands.json"

        try:
            commands = []
            if testing_log.exists():
                with open(testing_log, 'r') as f:
                    commands = json.load(f)

            commands.append({
                "timestamp": datetime.utcnow().isoformat(),
                "command": command,
                "mode": settings.gateway_mode
            })

            with open(testing_log, 'w') as f:
                json.dump(commands, f, indent=2)

        except Exception as e:
            logger.error(f"Error logging testing command: {e}")

    async def _log_drift(self, drifts: List[str]):
        """Log detected drift."""
        try:
            drift_log = []
            if self.drift_log_file.exists():
                with open(self.drift_log_file, 'r') as f:
                    drift_log = json.load(f)

            drift_log.append({
                "timestamp": datetime.utcnow().isoformat(),
                "drifts": drifts,
                "mode": settings.gateway_mode
            })

            with open(self.drift_log_file, 'w') as f:
                json.dump(drift_log, f, indent=2)

        except Exception as e:
            logger.error(f"Error logging drift: {e}")

# Global instance
state_manager = IptablesStateManager()