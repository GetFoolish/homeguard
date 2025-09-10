"""Database connection and session management."""

import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import event, text
from sqlalchemy.engine import Engine

from .models import Base
from ..config.settings import settings

logger = logging.getLogger(__name__)


# Create async engine with SQLite WAL mode for crash safety
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    future=True,
    # SQLite specific settings for better performance and safety
    connect_args={
        "check_same_thread": False,
    } if "sqlite" in settings.database_url else {}
)

# Create session factory
async_session_maker = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragmas for better performance and crash safety."""
    if "sqlite" in str(engine.url):
        cursor = dbapi_connection.cursor()
        # Enable WAL mode for better concurrent access and crash safety
        cursor.execute("PRAGMA journal_mode=WAL")
        # Set synchronous to NORMAL for good balance of safety and performance
        cursor.execute("PRAGMA synchronous=NORMAL") 
        # Enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys=ON")
        # Optimize for SSD storage
        cursor.execute("PRAGMA temp_store=memory")
        cursor.execute("PRAGMA mmap_size=268435456")  # 256MB
        cursor.close()
        logger.info("SQLite pragmas configured for optimal performance and safety")


async def create_tables():
    """Create database tables if they don't exist."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
        logger.info("Database tables created successfully")
    except Exception as e:
        # Handle "table already exists" as success - this is expected during restarts
        if "already exists" in str(e).lower():
            logger.info("Database tables already exist - continuing")
        else:
            logger.error(f"Failed to create database tables: {e}")
            raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get database session.
    
    Yields:
        AsyncSession: Database session
    """
    async with async_session_maker() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


class DatabaseManager:
    """Database manager for handling connections and operations."""
    
    def __init__(self):
        """Initialize database manager."""
        self.engine = engine
        self.session_maker = async_session_maker
    
    async def initialize(self):
        """Initialize database and create tables."""
        await create_tables()
        logger.info("Database manager initialized")
    
    async def health_check(self) -> bool:
        """
        Check database health.
        
        Returns:
            bool: True if database is accessible, False otherwise
        """
        try:
            async with self.session_maker() as session:
                # Simple query to check if database is accessible
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def backup_state(self, key: str, value: str):
        """
        Backup system state for crash recovery.
        
        Args:
            key: State key identifier
            value: State value (usually JSON)
        """
        try:
            from .models import SystemState
            async with self.session_maker() as session:
                # Update or insert state
                state = await session.get(SystemState, key)
                if state:
                    state.value = value
                else:
                    state = SystemState(key=key, value=value)
                    session.add(state)
                
                await session.commit()
                logger.debug(f"System state backed up: {key}")
        except Exception as e:
            logger.error(f"Failed to backup system state {key}: {e}")
    
    async def restore_state(self, key: str) -> str | None:
        """
        Restore system state after crash.
        
        Args:
            key: State key identifier
            
        Returns:
            str | None: State value or None if not found
        """
        try:
            from .models import SystemState
            async with self.session_maker() as session:
                state = await session.get(SystemState, key)
                if state:
                    logger.debug(f"System state restored: {key}")
                    return state.value
                return None
        except Exception as e:
            logger.error(f"Failed to restore system state {key}: {e}")
            return None
    
    async def cleanup_expired_devices(self):
        """Clean up expired device access records."""
        try:
            from .models import Device
            from datetime import datetime
            
            async with self.session_maker() as session:
                # Find devices with expired access
                from sqlalchemy import select, and_
                
                stmt = select(Device).where(
                    and_(
                        Device.is_authorized == True,
                        Device.access_expires_at != None,
                        Device.access_expires_at < datetime.utcnow()
                    )
                )
                
                result = await session.execute(stmt)
                expired_devices = result.scalars().all()
                
                for device in expired_devices:
                    device.revoke_access()
                    logger.info(f"Revoked expired access for device: {device.mac_address}")
                
                await session.commit()
                logger.info(f"Cleaned up {len(expired_devices)} expired device access records")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired devices: {e}")


# Global database manager instance
db_manager = DatabaseManager()