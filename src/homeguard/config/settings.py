"""Configuration settings for homeguard."""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Dict, Optional
import os
import yaml
from pathlib import Path


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Database settings
    database_url: str = Field(
        default="sqlite+aiosqlite:///homeguard.db",
        description="Database connection URL"
    )
    
    # Network settings
    gateway_interface: str = Field(
        default="eth1",
        description="Network interface for gateway (LAN side)"
    )
    client_interface: str = Field(
        default="eth1",
        description="Network interface for clients (LAN side)"
    )
    gateway_ip: str = Field(
        default="192.168.2.1",
        description="Gateway IP address (LAN side)"
    )
    dhcp_range_start: str = Field(
        default="192.168.2.100",
        description="DHCP range start"
    )
    dhcp_range_end: str = Field(
        default="192.168.2.200",
        description="DHCP range end"
    )
    
    # TOTP settings
    totp_secret_length: int = Field(
        default=32,
        description="Length of TOTP secrets"
    )
    totp_durations: Dict[str, int] = Field(
        default={
            "15min": 900,
            "30min": 1800, 
            "1hr": 3600,
            "2hr": 7200,
            "4hr": 14400,
            "24hr": 86400,
            "1week": 604800,
            "forever": -1
        },
        description="Available TOTP access durations in seconds"
    )
    
    # Web interface settings
    web_host: str = Field(default="0.0.0.0", description="Web server host")
    web_port: int = Field(default=8081, description="Web server port (admin interface)")
    admin_username: str = Field(default="admin", description="Admin username")
    admin_password: str = Field(default="admin123", description="Admin password")
    
    # IoT Network Exemptions
    iot_exempted_networks: List[str] = Field(
        default=["networknews", "arkanet_iot"],
        description="WiFi network names that bypass TOTP authentication"
    )
    iot_exempted_mac_prefixes: List[str] = Field(
        default=[],
        description="MAC address prefixes for IoT devices (e.g., ['aa:bb:cc', 'dd:ee:ff'])"
    )
    iot_exempted_device_names: List[str] = Field(
        default=[],
        description="Device hostnames that bypass authentication (e.g., ['smart-bulb', 'alexa'])"
    )

    # Google Sheets integration
    google_sheets_id: str = Field(
        default="",
        description="Google Sheets ID for filtering rules"
    )
    google_service_account_path: str = Field(
        default="",
        description="Path to Google service account JSON file"
    )
    sheets_poll_interval: int = Field(
        default=600,
        description="Google Sheets polling interval in seconds"
    )
    
    # Traffic filtering
    dns_blocked_domains: List[str] = Field(
        default=[],
        description="List of blocked DNS domains"
    )
    blocked_keywords: List[str] = Field(
        default=[],
        description="List of blocked content keywords"
    )
    blocked_services: List[str] = Field(
        default=["youtube_shorts", "gaming_servers"],
        description="List of blocked services"
    )
    
    # Service settings
    auto_recovery: bool = Field(
        default=True,
        description="Enable automatic service recovery"
    )
    health_check_interval: int = Field(
        default=30,
        description="Health check interval in seconds"
    )
    max_restart_attempts: int = Field(
        default=3,
        description="Maximum restart attempts before giving up"
    )
    
    # Execution mode settings
    execution_mode: str = Field(
        default="live",
        description="Execution mode: 'testing' (generate JSON) or 'live' (apply rules)"
    )

    # Gateway mode settings
    gateway_mode: str = Field(
        default="totp_testing",
        description="Gateway mode: 'transparent', 'totp_testing', or 'totp_enabled'"
    )
    testing_ip: Optional[str] = Field(
        default="192.168.2.52",
        description="IP address to test TOTP on when in testing mode (e.g., '192.168.2.52')"
    )
    emergency_mode: bool = Field(
        default=False,
        description="Emergency transparent mode (bypasses all blocking)"
    )

    # Development settings
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    class Config:
        env_file = ".env"
        env_prefix = "homeguard_"


def load_persistent_config() -> dict:
    """Load configuration from persistent YAML file."""
    config_path = Path("/etc/homeguard/config.yaml")

    if not config_path.exists():
        return {}

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Flatten the config structure for pydantic
        flattened = {}

        # Top-level mode
        if 'mode' in config:
            flattened['gateway_mode'] = config['mode']

        # Mode-specific settings
        current_mode = config.get('mode', 'transparent')
        mode_config = config.get('modes', {}).get(current_mode, {})

        if 'testing_ip' in mode_config:
            flattened['testing_ip'] = mode_config['testing_ip']

        # Network settings
        network = config.get('network', {})
        if 'gateway_ip' in network:
            flattened['gateway_ip'] = network['gateway_ip']
        if 'web_port' in network:
            flattened['web_port'] = network['web_port']
        if 'interface' in network:
            flattened['gateway_interface'] = network['interface']
            flattened['client_interface'] = network['interface']
        if 'dhcp_range_start' in network:
            flattened['dhcp_range_start'] = network['dhcp_range_start']
        if 'dhcp_range_end' in network:
            flattened['dhcp_range_end'] = network['dhcp_range_end']

        # App settings
        app = config.get('app', {})
        if 'database_url' in app:
            flattened['database_url'] = app['database_url']
        if 'log_level' in app:
            flattened['log_level'] = app['log_level']
        if 'debug' in app:
            flattened['debug'] = app['debug']

        # TOTP settings
        totp = config.get('totp', {})
        if 'secret_length' in totp:
            flattened['totp_secret_length'] = totp['secret_length']
        if 'durations' in totp:
            flattened['totp_durations'] = totp['durations']

        # Admin settings
        admin = config.get('admin', {})
        if 'username' in admin:
            flattened['admin_username'] = admin['username']
        if 'password' in admin:
            flattened['admin_password'] = admin['password']

        # IoT exemption settings
        iot = config.get('iot', {})
        if 'exempted_networks' in iot:
            flattened['iot_exempted_networks'] = iot['exempted_networks']
        if 'exempted_device_names' in iot:
            flattened['iot_exempted_device_names'] = iot['exempted_device_names']
        if 'exempted_mac_prefixes' in iot:
            flattened['iot_exempted_mac_prefixes'] = iot['exempted_mac_prefixes']

        return flattened

    except Exception as e:
        print(f"Warning: Could not load config file {config_path}: {e}")
        return {}


def save_persistent_config(settings_instance):
    """Save current settings to the persistent config file."""
    try:
        config_path = Path("/etc/homeguard/config.yaml")
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing config or create new one
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        # Update IoT exemption settings
        if 'iot' not in config:
            config['iot'] = {}

        config['iot']['exempted_networks'] = settings_instance.iot_exempted_networks
        config['iot']['exempted_device_names'] = settings_instance.iot_exempted_device_names
        config['iot']['exempted_mac_prefixes'] = settings_instance.iot_exempted_mac_prefixes

        # Write back to file
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        return True

    except Exception as e:
        print(f"Error: Could not save config file {config_path}: {e}")
        return False


class EnhancedSettings(Settings):
    """Settings that load from persistent config file first, then environment variables."""

    def __init__(self, **kwargs):
        # Load from persistent config file first
        config_overrides = load_persistent_config()

        # Merge with any provided kwargs (environment variables take precedence)
        merged = {**config_overrides, **kwargs}

        super().__init__(**merged)


# Global settings instance
settings = EnhancedSettings()