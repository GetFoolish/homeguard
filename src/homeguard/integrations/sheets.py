"""Google Sheets integration for dynamic rule management."""

import json
import logging
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import gspread
    from google.auth.exceptions import GoogleAuthError
    GSPREAD_AVAILABLE = True
except ImportError:
    GSPREAD_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class SheetsRule:
    """Rule structure from Google Sheets."""
    rule_type: str      # domain, keyword, url_pattern, ip
    pattern: str        # The pattern to match
    action: str         # block, allow, log_only
    enabled: bool       # True/False
    description: str    # Human-readable description
    added_by: str       # Who added this rule
    added_date: str     # When it was added
    phase: str          # Which phase(s) this applies to


class SheetsRuleManager:
    """
    Manages dynamic rule synchronization with Google Sheets.
    
    Expected Google Sheets format:
    Column A: Rule Type (domain, keyword, url_pattern, ip)
    Column B: Pattern (the actual pattern to match)
    Column C: Action (block, allow, log_only)
    Column D: Enabled (TRUE/FALSE)
    Column E: Description
    Column F: Added By
    Column G: Added Date
    Column H: Phase (1,2,3,4,5,6 or "all")
    """
    
    def __init__(self, config_dir: str = "/etc/homeguard"):
        """Initialize Google Sheets rule manager."""
        self.config_dir = Path(config_dir)
        self.credentials_file = Path("/home/raspberrypi/CODE_STUFF/secrets/google_sheets_api_key.json")
        self.config_file = self.config_dir / "sheets_config.json"
        self.cache_file = self.config_dir / "sheets_cache.json"
        
        self.spreadsheet_id = None
        self.worksheet_names = ["URLs", "Keywords"]  # Both sheets to sync
        self.client = None
        self.spreadsheet = None
        self.worksheets = {}
        
        self.is_active = False
        self.last_sync = None
        self.sync_interval = 300  # 5 minutes
        self.cached_rules: List[SheetsRule] = []
        self.sync_task = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load Google Sheets configuration."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                self.spreadsheet_id = config.get("spreadsheet_id")
                self.worksheet_name = config.get("worksheet_name", "Rules")
                self.sync_interval = config.get("sync_interval", 300)
                
                logger.info(f"Loaded Sheets config: {self.spreadsheet_id}")
            else:
                logger.info("No Google Sheets configuration found")
                self._create_default_config()
                
        except Exception as e:
            logger.error(f"Error loading Sheets config: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default Google Sheets configuration."""
        try:
            default_config = {
                "spreadsheet_id": "YOUR_SPREADSHEET_ID_HERE",
                "worksheet_name": "Rules",
                "sync_interval": 300,
                "last_setup": datetime.utcnow().isoformat(),
                "instructions": {
                    "step_1": "Create a Google Sheet with columns: Rule Type, Pattern, Action, Enabled, Description, Added By, Added Date, Phase",
                    "step_2": "Share the sheet with the service account email from credentials",
                    "step_3": "Copy the spreadsheet ID from the URL",
                    "step_4": "Update spreadsheet_id in this config file",
                    "step_5": "Place service account credentials in google_sheets_credentials.json"
                }
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            logger.info(f"Created default Sheets config at {self.config_file}")
            
        except Exception as e:
            logger.error(f"Error creating default config: {e}")
    
    async def initialize(self) -> bool:
        """Initialize Google Sheets connection."""
        try:
            if not GSPREAD_AVAILABLE:
                logger.error("gspread library not available. Install with: pip install gspread")
                return False
            
            if not self.credentials_file.exists():
                logger.warning(f"Google Sheets credentials not found at {self.credentials_file}")
                logger.info("To set up Google Sheets integration:")
                logger.info("1. Create a service account in Google Cloud Console")
                logger.info("2. Download the credentials JSON file")
                logger.info(f"3. Save it as {self.credentials_file}")
                logger.info("4. Share your Google Sheet with the service account email")
                return False
            
            if not self.spreadsheet_id or self.spreadsheet_id == "YOUR_SPREADSHEET_ID_HERE":
                logger.warning("Google Sheets spreadsheet ID not configured")
                logger.info(f"Please update {self.config_file} with your spreadsheet ID")
                return False
            
            # Initialize Google Sheets client
            self.client = gspread.service_account(filename=str(self.credentials_file))
            self.spreadsheet = self.client.open_by_key(self.spreadsheet_id)
            
            # Get both worksheets
            for sheet_name in self.worksheet_names:
                try:
                    self.worksheets[sheet_name] = self.spreadsheet.worksheet(sheet_name)
                    logger.info(f"Found worksheet: {sheet_name}")
                except gspread.WorksheetNotFound:
                    logger.warning(f"Worksheet '{sheet_name}' not found in spreadsheet")
            
            logger.info("✅ Google Sheets integration initialized")
            return True
            
        except GoogleAuthError as e:
            logger.error(f"Google authentication error: {e}")
            logger.info("Check your service account credentials and permissions")
            return False
        except Exception as e:
            logger.error(f"Error initializing Google Sheets: {e}")
            return False
    
    async def start(self):
        """Start the Google Sheets rule manager."""
        try:
            logger.info("Starting Google Sheets Rule Manager...")
            
            # Initialize connection
            if not await self.initialize():
                logger.warning("Google Sheets not available - running without dynamic rules")
                return
            
            # Load cached rules
            await self._load_cached_rules()
            
            # Start periodic sync
            self.sync_task = asyncio.create_task(self._sync_loop())
            
            self.is_active = True
            logger.info("✅ Google Sheets Rule Manager started")
            
        except Exception as e:
            logger.error(f"Failed to start Google Sheets Rule Manager: {e}")
            # Continue without Sheets integration
    
    async def stop(self):
        """Stop the Google Sheets rule manager."""
        logger.info("Stopping Google Sheets Rule Manager...")
        
        self.is_active = False
        
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Google Sheets Rule Manager stopped")
    
    async def _setup_worksheet_headers(self):
        """Set up the worksheet with proper headers."""
        try:
            headers = [
                "Rule Type",
                "Pattern", 
                "Action",
                "Enabled",
                "Description",
                "Added By",
                "Added Date",
                "Phase"
            ]
            
            # Update headers in first row
            self.worksheet.update('A1:H1', [headers])
            
            # Add example rows
            example_rows = [
                ["domain", "example.com", "block", "TRUE", "Block example.com", "admin", datetime.utcnow().strftime("%Y-%m-%d"), "all"],
                ["keyword", "badword", "block", "TRUE", "Block content with badword", "admin", datetime.utcnow().strftime("%Y-%m-%d"), "4,5,6"],
                ["url_pattern", ".*\\.ads\\..*", "block", "FALSE", "Block ad URLs (disabled)", "admin", datetime.utcnow().strftime("%Y-%m-%d"), "all"]
            ]
            
            self.worksheet.update('A2:H4', example_rows)
            
            logger.info("Worksheet headers and examples set up")
            
        except Exception as e:
            logger.error(f"Error setting up worksheet headers: {e}")
    
    async def _sync_loop(self):
        """Background task for periodic rule synchronization."""
        while self.is_active:
            try:
                await self.sync_rules()
                await asyncio.sleep(self.sync_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def sync_rules(self) -> Tuple[bool, str]:
        """
        Synchronize rules from Google Sheets.
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if not self.worksheets:
                return False, "Google Sheets not initialized"
            
            logger.info("Syncing rules from Google Sheets...")
            
            new_rules = []
            
            # Process URLs sheet
            if "URLs" in self.worksheets:
                try:
                    url_records = self.worksheets["URLs"].get_all_values()
                    for i, row in enumerate(url_records):
                        if not row or not row[0].strip():  # Skip empty rows only
                            continue
                        
                        url_pattern = row[0].strip()
                        if url_pattern:
                            rule = SheetsRule(
                                rule_type="domain",
                                pattern=url_pattern,
                                action="block",
                                enabled=True,
                                description=f"Block URL: {url_pattern}",
                                added_by="sheets_sync",
                                added_date=datetime.utcnow().strftime("%Y-%m-%d"),
                                phase="all"
                            )
                            new_rules.append(rule)
                    
                    logger.info(f"Loaded {len([r for r in new_rules if r.rule_type == 'domain'])} URLs from sheet")
                except Exception as e:
                    logger.error(f"Error reading URLs sheet: {e}")
            
            # Process Keywords sheet  
            if "Keywords" in self.worksheets:
                try:
                    keyword_records = self.worksheets["Keywords"].get_all_values()
                    for i, row in enumerate(keyword_records):
                        if not row or not row[0].strip():  # Skip empty rows only
                            continue
                        
                        keyword = row[0].strip()
                        if keyword:
                            rule = SheetsRule(
                                rule_type="keyword",
                                pattern=keyword,
                                action="block", 
                                enabled=True,
                                description=f"Block keyword: {keyword}",
                                added_by="sheets_sync",
                                added_date=datetime.utcnow().strftime("%Y-%m-%d"),
                                phase="all"
                            )
                            new_rules.append(rule)
                    
                    logger.info(f"Loaded {len([r for r in new_rules if r.rule_type == 'keyword'])} keywords from sheet")
                except Exception as e:
                    logger.error(f"Error reading Keywords sheet: {e}")
            
            # Update cached rules
            old_count = len(self.cached_rules)
            self.cached_rules = new_rules
            new_count = len(self.cached_rules)
            
            # Save to cache
            await self._save_cached_rules()
            
            self.last_sync = datetime.utcnow()
            
            message = f"Synced {new_count} rules from Google Sheets (was {old_count})"
            logger.info(message)
            
            return True, message
            
        except Exception as e:
            error_msg = f"Error syncing from Google Sheets: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def _validate_rule(self, rule: SheetsRule) -> bool:
        """Validate a rule from Google Sheets."""
        # Check required fields
        if not rule.rule_type or not rule.pattern:
            return False
        
        # Check valid rule types
        valid_types = ["domain", "keyword", "url_pattern", "ip"]
        if rule.rule_type not in valid_types:
            return False
        
        # Check valid actions
        valid_actions = ["block", "allow", "log_only"]
        if rule.action not in valid_actions:
            return False
        
        return True
    
    async def _load_cached_rules(self):
        """Load rules from cache file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                
                self.cached_rules = [
                    SheetsRule(**rule_data) 
                    for rule_data in cache_data.get("rules", [])
                ]
                
                cache_time = cache_data.get("last_sync")
                if cache_time:
                    self.last_sync = datetime.fromisoformat(cache_time)
                
                logger.info(f"Loaded {len(self.cached_rules)} cached rules")
                
        except Exception as e:
            logger.error(f"Error loading cached rules: {e}")
            self.cached_rules = []
    
    async def _save_cached_rules(self):
        """Save rules to cache file."""
        try:
            cache_data = {
                "rules": [asdict(rule) for rule in self.cached_rules],
                "last_sync": self.last_sync.isoformat() if self.last_sync else None,
                "sync_interval": self.sync_interval
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving cached rules: {e}")
    
    def get_rules_for_phase(self, phase: int) -> List[SheetsRule]:
        """Get rules applicable to a specific phase."""
        applicable_rules = []
        
        for rule in self.cached_rules:
            if not rule.enabled:
                continue
            
            # Check if rule applies to this phase
            if rule.phase == "all":
                applicable_rules.append(rule)
            else:
                # Parse phase specification (e.g., "4,5,6" or "1-3")
                if self._rule_applies_to_phase(rule.phase, phase):
                    applicable_rules.append(rule)
        
        return applicable_rules
    
    def _rule_applies_to_phase(self, phase_spec: str, target_phase: int) -> bool:
        """Check if a rule applies to a specific phase."""
        try:
            # Handle comma-separated phases (e.g., "4,5,6")
            if "," in phase_spec:
                phases = [int(p.strip()) for p in phase_spec.split(",")]
                return target_phase in phases
            
            # Handle single phase
            if phase_spec.isdigit():
                return int(phase_spec) == target_phase
            
            # Handle range (e.g., "1-3")
            if "-" in phase_spec:
                start, end = phase_spec.split("-")
                return int(start) <= target_phase <= int(end)
            
            return False
            
        except Exception:
            return False
    
    async def add_rule_to_sheet(self, rule: SheetsRule) -> Tuple[bool, str]:
        """
        Add a new rule to the Google Sheet.
        
        Args:
            rule: The rule to add
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if not self.worksheet:
                return False, "Google Sheets not initialized"
            
            # Add to next empty row
            row_data = [
                rule.rule_type,
                rule.pattern,
                rule.action,
                "TRUE" if rule.enabled else "FALSE",
                rule.description,
                rule.added_by,
                rule.added_date or datetime.utcnow().strftime("%Y-%m-%d"),
                rule.phase
            ]
            
            self.worksheet.append_row(row_data)
            
            logger.info(f"Added rule to Google Sheets: {rule.rule_type}:{rule.pattern}")
            
            # Trigger sync to update cache
            await self.sync_rules()
            
            return True, "Rule added successfully"
            
        except Exception as e:
            error_msg = f"Error adding rule to Google Sheets: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_stats(self) -> Dict[str, any]:
        """Get Google Sheets integration statistics."""
        return {
            "is_active": self.is_active,
            "spreadsheet_id": self.spreadsheet_id,
            "worksheet_name": self.worksheet_name,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "sync_interval": self.sync_interval,
            "cached_rules_count": len(self.cached_rules),
            "enabled_rules_count": len([r for r in self.cached_rules if r.enabled]),
            "rules_by_type": self._get_rules_by_type_stats()
        }
    
    def _get_rules_by_type_stats(self) -> Dict[str, int]:
        """Get statistics of rules by type."""
        stats = {}
        for rule in self.cached_rules:
            if rule.enabled:
                if rule.rule_type in stats:
                    stats[rule.rule_type] += 1
                else:
                    stats[rule.rule_type] = 1
        return stats
    
    def force_sync(self) -> asyncio.Task:
        """Force an immediate synchronization."""
        return asyncio.create_task(self.sync_rules())


# Global sheets rule manager instance
sheets_manager = SheetsRuleManager()