"""
MCP Auth Client
Shared OAuth authentication client for MCP servers.
"""
from .client import AuthClient
from .decorators import require_auth
from .exceptions import AuthRequiredException, TokenExpiredException, AuthClientError

__version__ = "1.0.0"
__all__ = [
    "AuthClient",
    "require_auth",
    "AuthRequiredException",
    "TokenExpiredException",
    "AuthClientError"
]
