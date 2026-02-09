"""
Custom Exceptions for MCP Auth Client
"""


class AuthClientError(Exception):
    """Base exception for auth client errors."""
    pass


class AuthRequiredException(AuthClientError):
    """
    Raised when user authentication is required.
    Contains the auth URL for user to visit.
    """
    def __init__(self, auth_url: str, session_id: str = None, message: str = None):
        self.auth_url = auth_url
        self.session_id = session_id
        self.message = message or f"Authentication required. Please visit: {auth_url}"
        super().__init__(self.message)
    
    def __str__(self):
        return f"🔐 AUTHENTICATION REQUIRED\n\nPlease visit this URL to authenticate:\n{self.auth_url}\n\nAfter completing authentication, say 'done' or 'ready' to continue."


class TokenExpiredException(AuthClientError):
    """Raised when token is expired and refresh failed."""
    def __init__(self, message: str = "Token expired and refresh failed. Re-authentication required."):
        super().__init__(message)


class TokenNotFoundError(AuthClientError):
    """Raised when no token exists for user."""
    def __init__(self, user_email: str, provider: str):
        self.user_email = user_email
        self.provider = provider
        super().__init__(f"No credentials found for {user_email} with provider {provider}")


class GatewayConnectionError(AuthClientError):
    """Raised when connection to Auth Gateway fails."""
    def __init__(self, message: str = "Failed to connect to Auth Gateway"):
        super().__init__(message)


class InvalidAPIKeyError(AuthClientError):
    """Raised when API key is invalid."""
    def __init__(self):
        super().__init__("Invalid API key for Auth Gateway")
