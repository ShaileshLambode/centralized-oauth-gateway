"""
Authentication Decorators
Decorators for MCP tool functions to handle authentication.
"""
import functools
import logging
from typing import Callable, Any

from .client import AuthClient
from .exceptions import AuthRequiredException

logger = logging.getLogger(__name__)


def require_auth(
    auth_client: AuthClient,
    provider: str,
    email_param: str = "user_email"
):
    """
    Decorator that ensures authentication before tool execution.
    
    If user is not authenticated, raises AuthRequiredException with
    the auth URL for them to visit.
    
    Args:
        auth_client: AuthClient instance
        provider: OAuth provider to authenticate with (e.g., 'google')
        email_param: Name of the function parameter containing user email
    
    Usage:
        @server.tool()
        @require_auth(auth_client, provider="google")
        async def my_tool(user_email: str, arg1: str):
            token = await auth_client.get_token("google", user_email)
            # ... use token ...
    
    The decorator:
        1. Extracts user_email from function arguments
        2. Checks if user is authenticated with Auth Gateway
        3. If not authenticated → starts OAuth flow → raises AuthRequiredException
        4. If authenticated → proceeds with function execution
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user email from kwargs or positional args
            user_email = None
            
            # Check kwargs first
            if email_param in kwargs:
                user_email = kwargs[email_param]
            else:
                # Try to get from function signature
                import inspect
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())
                
                if email_param in params:
                    param_index = params.index(email_param)
                    if param_index < len(args):
                        user_email = args[param_index]
            
            if not user_email:
                logger.error(f"Missing {email_param} parameter for authentication")
                raise ValueError(f"Missing required parameter: {email_param}")
            
            # Check authentication
            is_authed = await auth_client.is_authenticated(provider, user_email)
            
            if not is_authed:
                logger.info(f"User {user_email} not authenticated with {provider}, initiating OAuth")
                
                # Start OAuth flow
                auth_info = await auth_client.init_oauth(provider, user_email)
                
                # Raise exception with auth URL
                raise AuthRequiredException(
                    auth_url=auth_info.auth_url,
                    session_id=auth_info.session_id
                )
            
            # User is authenticated, proceed with function
            logger.debug(f"User {user_email} authenticated with {provider}")
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_auth_sync(
    auth_client: AuthClient,
    provider: str,
    email_param: str = "user_email"
):
    """
    Synchronous version of require_auth decorator.
    For non-async tool functions.
    
    Note: This still makes async calls internally using asyncio.run()
    """
    import asyncio
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user email
            user_email = kwargs.get(email_param)
            
            if not user_email:
                import inspect
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())
                if email_param in params:
                    param_index = params.index(email_param)
                    if param_index < len(args):
                        user_email = args[param_index]
            
            if not user_email:
                raise ValueError(f"Missing required parameter: {email_param}")
            
            # Check authentication
            is_authed = asyncio.run(auth_client.is_authenticated(provider, user_email))
            
            if not is_authed:
                auth_info = asyncio.run(auth_client.init_oauth(provider, user_email))
                raise AuthRequiredException(
                    auth_url=auth_info.auth_url,
                    session_id=auth_info.session_id
                )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator
