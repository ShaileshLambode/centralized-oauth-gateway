"""
Pydantic Schemas for Auth API
Request and response models for OAuth endpoints.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID


# ============================================
# Request Schemas
# ============================================

class AuthInitRequest(BaseModel):
    """Request to initialize OAuth flow."""
    provider: str = Field(..., description="OAuth provider: 'google', 'microsoft', etc.")
    user_email: EmailStr = Field(..., description="User's email address")
    scopes: Optional[List[str]] = Field(None, description="Optional specific scopes to request")


class TokenRequest(BaseModel):
    """Request to get access token."""
    provider: str = Field(..., description="OAuth provider")
    user_email: EmailStr = Field(..., description="User's email address")


class RevokeRequest(BaseModel):
    """Request to revoke credentials."""
    provider: str = Field(..., description="OAuth provider")
    user_email: EmailStr = Field(..., description="User's email address")


# ============================================
# Response Schemas
# ============================================

class AuthInitResponse(BaseModel):
    """Response from OAuth init."""
    auth_url: str = Field(..., description="URL to redirect user for OAuth consent")
    session_id: UUID = Field(..., description="Session ID for tracking")
    expires_at: datetime = Field(..., description="Session expiry time")


class AuthStatusResponse(BaseModel):
    """Response from status check."""
    status: str = Field(..., description="pending, completed, or failed")
    session_id: UUID = Field(..., description="Session ID")
    user_email: Optional[str] = Field(None, description="User email (when completed)")
    provider: Optional[str] = Field(None, description="Provider (when completed)")
    error: Optional[str] = Field(None, description="Error message (when failed)")
    expires_at: Optional[datetime] = Field(None, description="Expiry (when pending)")


class TokenResponse(BaseModel):
    """Response with access token."""
    access_token: str = Field(..., description="OAuth access token")
    token_type: str = Field(default="Bearer")
    expires_at: Optional[datetime] = Field(None, description="Token expiry time")
    scopes: Optional[List[str]] = Field(None, description="Granted scopes")


class TokenErrorResponse(BaseModel):
    """Error response when token not available."""
    error: str = Field(..., description="Error code: not_authenticated, refresh_failed")
    message: str = Field(..., description="Human-readable error message")
    auth_required: bool = Field(default=True)


class ProviderInfo(BaseModel):
    """Info about a single authorized provider."""
    provider: str
    scopes: Optional[List[str]]
    authenticated_at: datetime
    token_expires_at: Optional[datetime]


class ProvidersListResponse(BaseModel):
    """List of user's authorized providers."""
    user_email: str
    providers: List[ProviderInfo]


class RevokeResponse(BaseModel):
    """Response from credential revocation."""
    success: bool
    message: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy")
    database: str = Field(default="connected")
    encryption: str = Field(default="operational")
    version: str = Field(default="1.0.0")
    timestamp: datetime


class ErrorResponse(BaseModel):
    """Generic error response."""
    error: str
    message: str
    detail: Optional[str] = None
