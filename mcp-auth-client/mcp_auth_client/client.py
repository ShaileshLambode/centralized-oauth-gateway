"""
Auth Client
Main client for interacting with Auth Gateway.
"""
import logging
from typing import Optional, Dict, List
from dataclasses import dataclass

import httpx

from .exceptions import (
    AuthRequiredException,
    TokenExpiredException,
    TokenNotFoundError,
    GatewayConnectionError,
    InvalidAPIKeyError
)

logger = logging.getLogger(__name__)


@dataclass
class TokenInfo:
    """Token information returned from gateway."""
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[str] = None
    scopes: Optional[List[str]] = None


@dataclass
class AuthSessionInfo:
    """OAuth session information."""
    auth_url: str
    session_id: str
    expires_at: str


class AuthClient:
    """
    Client for Auth Gateway communication.
    Used by MCP servers to manage OAuth authentication.
    """
    
    def __init__(
        self,
        gateway_url: str,
        api_key: str,
        timeout: float = 30.0
    ):
        """
        Initialize Auth Client.
        
        Args:
            gateway_url: URL of Auth Gateway (e.g., http://localhost:8000)
            api_key: API key for authentication
            timeout: Request timeout in seconds
        """
        self.gateway_url = gateway_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        
        self._headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        json: Optional[Dict] = None
    ) -> httpx.Response:
        """Make request to Auth Gateway."""
        url = f"{self.gateway_url}{endpoint}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self._headers,
                    json=json
                )
            return response
        except httpx.ConnectError as e:
            logger.error(f"Failed to connect to Auth Gateway: {e}")
            raise GatewayConnectionError(f"Cannot connect to Auth Gateway at {self.gateway_url}")
        except httpx.TimeoutException:
            raise GatewayConnectionError("Auth Gateway request timed out")
    
    async def is_authenticated(self, provider: str, user_email: str) -> bool:
        """
        Check if user has valid credentials for provider.
        
        Args:
            provider: OAuth provider (e.g., 'google')
            user_email: User's email address
            
        Returns:
            True if authenticated, False otherwise
        """
        try:
            response = await self._request(
                "POST",
                "/auth/token",
                json={"provider": provider, "user_email": user_email}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def get_token(self, provider: str, user_email: str) -> str:
        """
        Get valid access token for user.
        Auto-refreshes if token is expired.
        
        Args:
            provider: OAuth provider (e.g., 'google')
            user_email: User's email address
            
        Returns:
            Access token string
            
        Raises:
            AuthRequiredException: If user needs to authenticate
            TokenExpiredException: If refresh failed
        """
        logger.debug(f"Getting token for {user_email} ({provider})")
        
        response = await self._request(
            "POST",
            "/auth/token",
            json={"provider": provider, "user_email": user_email}
        )
        
        if response.status_code == 200:
            data = response.json()
            return data["access_token"]
        
        if response.status_code == 403:
            raise InvalidAPIKeyError()
        
        if response.status_code in (401, 404):
            # Need authentication
            data = response.json()
            error = data.get("detail", {})
            
            if isinstance(error, dict) and error.get("auth_required"):
                # Start OAuth flow
                auth_info = await self.init_oauth(provider, user_email)
                raise AuthRequiredException(
                    auth_url=auth_info.auth_url,
                    session_id=auth_info.session_id
                )
            
            raise TokenNotFoundError(user_email, provider)
        
        raise GatewayConnectionError(f"Unexpected response: {response.status_code}")
    
    async def init_oauth(
        self,
        provider: str,
        user_email: str,
        scopes: Optional[List[str]] = None
    ) -> AuthSessionInfo:
        """
        Initialize OAuth flow.
        
        Args:
            provider: OAuth provider (e.g., 'google')
            user_email: User's email address
            scopes: Optional specific scopes to request
            
        Returns:
            AuthSessionInfo with auth_url and session_id
        """
        logger.info(f"Initializing OAuth for {user_email} ({provider})")
        
        payload = {
            "provider": provider,
            "user_email": user_email
        }
        if scopes:
            payload["scopes"] = scopes
        
        response = await self._request("POST", "/auth/init", json=payload)
        
        if response.status_code == 200:
            data = response.json()
            return AuthSessionInfo(
                auth_url=data["auth_url"],
                session_id=data["session_id"],
                expires_at=data["expires_at"]
            )
        
        if response.status_code == 403:
            raise InvalidAPIKeyError()
        
        raise GatewayConnectionError(f"Failed to init OAuth: {response.status_code}")
    
    async def get_auth_status(self, session_id: str) -> Dict:
        """
        Check OAuth session status.
        
        Args:
            session_id: Session ID from init_oauth
            
        Returns:
            Status dict with 'status', 'user_email', 'provider'
        """
        response = await self._request("GET", f"/auth/status/{session_id}")
        
        if response.status_code == 200:
            return response.json()
        
        if response.status_code == 404:
            return {"status": "not_found", "error": "Session not found"}
        
        return {"status": "error", "error": f"Status code: {response.status_code}"}
    
    async def list_providers(self, user_email: str) -> List[Dict]:
        """
        List providers user has authenticated with.
        
        Args:
            user_email: User's email address
            
        Returns:
            List of provider info dicts
        """
        response = await self._request("GET", f"/auth/providers/{user_email}")
        
        if response.status_code == 200:
            data = response.json()
            return data.get("providers", [])
        
        return []
    
    async def revoke(self, provider: str, user_email: str) -> bool:
        """
        Revoke credentials for user.
        
        Args:
            provider: OAuth provider
            user_email: User's email address
            
        Returns:
            True if revoked, False otherwise
        """
        response = await self._request(
            "DELETE",
            "/auth/revoke",
            json={"provider": provider, "user_email": user_email}
        )
        
        return response.status_code == 200
