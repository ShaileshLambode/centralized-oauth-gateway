"""
Auth Gateway Configuration
Loads settings from environment variables with validation.
"""
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Optional, List
import os


class Settings(BaseSettings):
    """Auth Gateway configuration settings."""
    
    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:password@localhost:5432/auth_gateway",
        description="PostgreSQL connection string"
    )
    
    # Encryption
    AUTH_GATEWAY_ENCRYPTION_KEY: str = Field(
        ...,
        description="32-byte Fernet encryption key for token encryption"
    )
    AUTH_GATEWAY_ENCRYPTION_KEY_SALT: Optional[str] = Field(
        default=None,
        description="Optional salt for additional key derivation"
    )
    AUTH_GATEWAY_ROTATION_KEYS: Optional[str] = Field(
        default=None,
        description="Comma-separated old keys for key rotation"
    )
    
    # API Security
    AUTH_GATEWAY_API_KEY: str = Field(
        ...,
        description="API key for MCP server authentication"
    )
    
    # Google OAuth
    GOOGLE_CLIENT_ID: str = Field(
        ...,
        description="Google OAuth client ID"
    )
    GOOGLE_CLIENT_SECRET: str = Field(
        ...,
        description="Google OAuth client secret"
    )
    GOOGLE_REDIRECT_URI: str = Field(
        default="http://localhost:8000/auth/callback/google",
        description="OAuth callback URL"
    )
    
    # Server
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    ENVIRONMENT: str = Field(default="development")
    
    # Session settings
    SESSION_EXPIRY_MINUTES: int = Field(
        default=15,
        description="OAuth session expiry time"
    )
    TOKEN_REFRESH_BUFFER_SECONDS: int = Field(
        default=300,
        description="Refresh tokens this many seconds before expiry"
    )
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FORMAT: str = Field(default="json")
    
    @field_validator('AUTH_GATEWAY_ENCRYPTION_KEY')
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        """Validate encryption key format."""
        if len(v) < 32:
            raise ValueError("Encryption key must be at least 32 characters")
        return v
    
    @property
    def rotation_keys_list(self) -> List[str]:
        """Parse rotation keys from comma-separated string."""
        if self.AUTH_GATEWAY_ROTATION_KEYS:
            return [k.strip() for k in self.AUTH_GATEWAY_ROTATION_KEYS.split(",") if k.strip()]
        return []
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()
