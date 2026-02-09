"""
SQLAlchemy Models
Database models for OAuth credentials and sessions.
"""
import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Column, String, Text, DateTime,
    UniqueConstraint, CheckConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from database import Base


class OAuthCredential(Base):
    """
    Stored OAuth credentials per user.
    Tokens are encrypted at rest using Fernet.
    """
    __tablename__ = "oauth_credentials"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    profile_id = Column(String(255), nullable=False)  # EMAIL ADDRESS
    provider_id = Column(String(50), nullable=False)  # 'google', 'microsoft', etc.
    access_token = Column(Text, nullable=False)  # ENCRYPTED
    refresh_token = Column(Text)  # ENCRYPTED
    token_expiry = Column(DateTime(timezone=True))
    scopes = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('profile_id', 'provider_id', name='unique_user_provider'),
        CheckConstraint(
            r"profile_id ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'",
            name='valid_email'
        ),
        Index('idx_credentials_profile', 'profile_id'),
        Index('idx_credentials_expiry', 'token_expiry'),
    )
    
    def __repr__(self):
        return f"<OAuthCredential(profile_id='{self.profile_id}', provider='{self.provider_id}')>"


class OAuthSession(Base):
    """
    Pending OAuth sessions.
    Tracks OAuth flows from init to callback completion.
    """
    __tablename__ = "oauth_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    profile_id = Column(String(255), nullable=False)  # EMAIL ADDRESS
    provider_id = Column(String(50), nullable=False)  # 'google', 'microsoft', etc.
    state = Column(String(255), unique=True, nullable=False)  # CSRF token
    status = Column(String(20), default='pending')  # pending/completed/failed
    redirect_after = Column(Text)  # Optional redirect URL
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Constraints
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'completed', 'failed')",
            name='valid_status'
        ),
        Index('idx_sessions_state', 'state'),
        Index('idx_sessions_status', 'status', 'expires_at'),
    )
    
    def __repr__(self):
        return f"<OAuthSession(id='{self.id}', status='{self.status}')>"

