"""Configuration settings for Homeguard."""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Dict
import json
from pathlib import Path


class Settings(BaseSettings):
    """Application settings."""

    # Execution mode - ALWAYS use 'testing' for development
    execution_mode: str = Field(
        default="testing",
        description="Execution mode: 'testing' (print only) or 'live' (apply iptables)"
    )

    # System mode
    system_mode: str = Field(
        default="transparent",
        description="System mode: 'transparent' or 'totp'"
    )

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///homeguard.db",
        description="Database connection URL"
    )

    # Network settings
    gateway_ip: str = Field(
        default="192.168.2.1",
        description="Gateway IP address"
    )
    lan_interface: str = Field(
        default="eth1",
        description="LAN interface name"
    )
    wan_interface: str = Field(
        default="eth0",
        description="WAN interface name"
    )

    # Web interface
    web_host: str = Field(default="0.0.0.0", description="Web server host")
    web_port: int = Field(default=8081, description="Web server port")

    # TOTP settings
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

    # Logging
    log_file: str = Field(default="homeguard.log", description="Log file path")
    log_level: str = Field(default="INFO", description="Logging level")

    class Config:
        env_file = ".env"
        env_prefix = "homeguard_"


def load_config_file() -> dict:
    """Load persistent config from JSON file."""
    config_file = Path("homeguard_config.json")
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    return {}


def save_config_file(config: dict):
    """Save config to JSON file."""
    config_file = Path("homeguard_config.json")
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save config file: {e}")


class EnhancedSettings(Settings):
    """Settings that load from config file first."""

    def __init__(self, **kwargs):
        config_overrides = load_config_file()
        merged = {**config_overrides, **kwargs}
        super().__init__(**merged)


# Global settings instance
settings = EnhancedSettings()
