"""
FastAPI Dependencies
Shared dependencies for authentication, database, and encryption.
"""
from fastapi import Header, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db, async_session_maker
from encryption import EncryptionService, create_encryption_service


# ============================================
# Encryption Service Dependency
# ============================================

_encryption_service: EncryptionService = None


def get_encryption_service() -> EncryptionService:
    """Get or create encryption service singleton."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = create_encryption_service(
            primary_key=settings.AUTH_GATEWAY_ENCRYPTION_KEY,
            salt=settings.AUTH_GATEWAY_ENCRYPTION_KEY_SALT,
            rotation_keys=settings.rotation_keys_list
        )
    return _encryption_service


# ============================================
# API Key Authentication
# ============================================

async def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key", description="API key for authentication")
) -> str:
    """
    Verify API key from request header.
    Required for all MCP server requests.
    """
    if x_api_key != settings.AUTH_GATEWAY_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    return x_api_key


# ============================================
# Database Session Dependency
# ============================================

async def get_db_session() -> AsyncSession:
    """Get database session."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
