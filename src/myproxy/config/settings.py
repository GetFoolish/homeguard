"""Configuration settings for MyProxy."""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Dict
import os


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Database settings
    database_url: str = Field(
        default="sqlite+aiosqlite:///myproxy.db",
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
    
    # Gateway mode settings
    gateway_mode: str = Field(
        default="transparent",
        description="Gateway mode: 'transparent' or 'totp_enabled'"
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
        env_prefix = "MYPROXY_"


# Global settings instance
settings = Settings()