"""Database models for MyProxy."""

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
    is_authorized = Column(Boolean, default=False)      # Whether device has valid access
    access_granted_at = Column(DateTime, nullable=True) # When access was granted
    access_expires_at = Column(DateTime, nullable=True) # When access expires (None for forever)
    access_duration = Column(String(20), nullable=True) # Duration type (15min, 1hr, etc.)
    user_agent = Column(Text, nullable=True)            # Browser user agent if available
    device_type = Column(String(50), nullable=True)     # Device type (mobile, desktop, etc.)
    notes = Column(Text, nullable=True)                 # Admin notes about device
    
    def __repr__(self):
        return f"<Device(mac={self.mac_address}, ip={self.ip_address}, authorized={self.is_authorized})>"
    
    @property
    def is_access_valid(self) -> bool:
        """Check if device's access is still valid."""
        if not self.is_authorized:
            return False
        
        if self.access_expires_at is None:  # Forever access
            return True
            
        return datetime.utcnow() < self.access_expires_at
    
    def grant_access(self, duration_key: str, expires_at: Optional[datetime]):
        """Grant access to the device."""
        self.is_authorized = True
        self.access_granted_at = datetime.utcnow()
        self.access_expires_at = expires_at
        self.access_duration = duration_key
    
    def revoke_access(self):
        """Revoke access from the device."""
        self.is_authorized = False
        self.access_granted_at = None
        self.access_expires_at = None
        self.access_duration = None


class FilterRule(Base):
    """Model for content filtering rules."""
    
    __tablename__ = "filter_rules"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_type = Column(String(20), nullable=False)  # 'dns', 'keyword', 'service'
    rule_value = Column(String(255), nullable=False)  # The actual rule content
    is_active = Column(Boolean, default=True)        # Whether rule is active
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    source = Column(String(50), default="manual")    # 'manual', 'google_sheets'
    description = Column(Text, nullable=True)        # Description of the rule
    
    def __repr__(self):
        return f"<FilterRule(type={self.rule_type}, value={self.rule_value}, active={self.is_active})>"


class AccessLog(Base):
    """Model for logging access attempts and traffic."""
    
    __tablename__ = "access_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), nullable=False)
    ip_address = Column(String(15), nullable=True)
    event_type = Column(String(50), nullable=False)  # 'auth_attempt', 'access_granted', 'access_denied', 'traffic_blocked'
    event_details = Column(Text, nullable=True)      # JSON details about the event
    timestamp = Column(DateTime, default=func.now())
    user_agent = Column(Text, nullable=True)
    requested_url = Column(Text, nullable=True)      # For blocked traffic logs
    
    def __repr__(self):
        return f"<AccessLog(mac={self.mac_address}, event={self.event_type}, time={self.timestamp})>"


class SystemState(Base):
    """Model for storing system state for crash recovery."""
    
    __tablename__ = "system_state"
    
    key = Column(String(100), primary_key=True)      # State key identifier
    value = Column(Text, nullable=True)              # State value (JSON)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f"<SystemState(key={self.key}, updated={self.updated_at})>"