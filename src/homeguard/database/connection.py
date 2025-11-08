"""Database connection and session management."""

import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, database_url: str = "sqlite+aiosqlite:///homeguard.db"):
        """Initialize database manager."""
        self.database_url = database_url
        self.engine = create_async_engine(
            database_url,
            echo=False,
            future=True
        )
        self.async_session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def initialize(self):
        """Initialize database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully")

    async def close(self):
        """Close database connection."""
        await self.engine.dispose()
        logger.info("Database connection closed")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session context manager."""
        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Global database manager instance
db_manager = DatabaseManager()


# Dependency for FastAPI
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency to get database session."""
    async with db_manager.get_session() as session:
        yield session
