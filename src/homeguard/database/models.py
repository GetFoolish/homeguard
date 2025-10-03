"""Database models for Homeguard."""

from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional

Base = declarative_base()


class Device(Base):
    """Model for tracking network devices."""

    __tablename__ = "devices"

    mac_address = Column(String(17), primary_key=True)  # MAC address format: XX:XX:XX:XX:XX:XX
    ip_address = Column(String(15), nullable=True)      # Current IP address
    hostname = Column(String(255), nullable=True)       # Device hostname if available
    first_seen = Column(DateTime, default=func.now())   # First time device was seen
    last_seen = Column(DateTime, default=func.now())    # Last activity time

    # Access control fields
    access_status = Column(String(20), default="blocked")  # "granted", "blocked", "iot"
    access_granted_at = Column(DateTime, nullable=True)    # When access was granted
    access_expires_at = Column(DateTime, nullable=True)    # When access expires (None for forever/iot)
    access_duration = Column(String(20), nullable=True)    # Duration type (15min, 1hr, etc.)

    # Device metadata
    user_agent = Column(Text, nullable=True)            # Browser user agent if available
    device_type = Column(String(50), nullable=True)     # Device type (mobile, desktop, etc.)
    notes = Column(Text, nullable=True)                 # Admin notes about device

    def __repr__(self):
        return f"<Device(mac={self.mac_address}, ip={self.ip_address}, access={self.access_status})>"

    @property
    def is_access_valid(self) -> bool:
        """Check if device's access is still valid."""
        if self.access_status == "blocked":
            return False

        if self.access_status == "iot":
            return True

        if self.access_status == "granted":
            if self.access_expires_at is None:  # Forever access
                return True
            return datetime.utcnow() < self.access_expires_at

        return False

    def grant_access(self, duration_key: str, expires_at: Optional[datetime]):
        """Grant access to the device."""
        self.access_status = "granted"
        self.access_granted_at = datetime.utcnow()
        self.access_expires_at = expires_at
        self.access_duration = duration_key

    def block_access(self):
        """Block access from the device."""
        self.access_status = "blocked"
        self.access_granted_at = None
        self.access_expires_at = None
        self.access_duration = None

    def set_iot(self):
        """Set device as IOT device."""
        self.access_status = "iot"
        self.access_granted_at = datetime.utcnow()
        self.access_expires_at = None
        self.access_duration = None


class AccessLog(Base):
    """Model for logging access attempts and traffic."""

    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), nullable=False)
    ip_address = Column(String(15), nullable=True)
    event_type = Column(String(50), nullable=False)  # 'auth_attempt', 'access_granted', 'access_blocked', 'iot_added'
    event_details = Column(Text, nullable=True)      # JSON details about the event
    timestamp = Column(DateTime, default=func.now())

    def __repr__(self):
        return f"<AccessLog(mac={self.mac_address}, event={self.event_type}, time={self.timestamp})>"
