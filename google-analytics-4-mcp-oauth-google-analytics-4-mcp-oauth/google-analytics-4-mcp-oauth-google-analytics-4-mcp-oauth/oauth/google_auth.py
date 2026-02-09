"""
Google Analytics OAuth Authentication - Server-based callback handler
Implements authentication flow similar to google-ads-mcp-main
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Google Auth libraries
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# Allow OAuth scope to change (e.g. if extra scopes are granted by the user/project)
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

logger = logging.getLogger(__name__)

# Constants - Updated for Google Analytics
SCOPES = [
    'https://www.googleapis.com/auth/analytics',
    'https://www.googleapis.com/auth/analytics.readonly'
]

# Environment variables
GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH = os.environ.get("GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH")
GOOGLE_GA4_REDIRECT_URI = os.environ.get("GOOGLE_GA4_REDIRECT_URI")
GOOGLE_GA4_TOKEN_PATH = os.environ.get("GOOGLE_GA4_TOKEN_PATH", "./Google_Creds/tokens/")

# Global variables for session management
pending_auth_flows: Dict[str, Any] = {}
active_session_id: str = "default"



# Global variable to track authorization code from callback
_auth_code = None
_auth_error = None
_code_received_event = None


def get_config_path() -> Path:
    """Get the path to the session configuration file."""
    base_path = GOOGLE_GA4_TOKEN_PATH.rstrip('/')
    return Path(base_path).parent / "session_config.json"


def get_token_path(session_id: str) -> str:
    """
    Determine the token file path for a given session.
    
    Args:
        session_id: The session identifier
        
    Returns:
        Full path to the token file
    """
    base_path = GOOGLE_GA4_TOKEN_PATH.rstrip('/')
    p = Path(base_path)
    p.mkdir(exist_ok=True, parents=True)
    return str(p / f"{session_id}.json")


def load_active_session():
    """Load the active session ID from disk."""
    global active_session_id
    config_path = get_config_path()
    try:
        if config_path.exists():
            with open(config_path, "r") as f:
                config = json.load(f)
                active_session_id = config.get("active_session_id", "default")
                logger.info(f"Loaded active session from config: {active_session_id}")
    except Exception as e:
        logger.warning(f"Failed to load session config: {str(e)}")


def save_active_session(session_id: str):
    """Save the active session ID to disk."""
    global active_session_id
    config_path = get_config_path()
    try:
        config_path.parent.mkdir(exist_ok=True, parents=True)
        data = {"active_session_id": session_id}
        with open(config_path, "w") as f:
            json.dump(data, f)
        logger.info(f"Saved active session to config: {session_id}")
    except Exception as e:
        logger.warning(f"Failed to save session config: {str(e)}")


def resolve_session_id(session_id: str) -> str:
    """
    Resolve the effective session ID.
    Priority: Explicit > Active > Default
    
    Args:
        session_id: The session ID to check
        
    Returns:
        The resolved session ID
    """
    global active_session_id
    
    # Explicit session_id provided (not default)
    if session_id != "default":
        return session_id
    
    # Use active session if set
    if active_session_id != "default":
        return active_session_id
    
    return "default"



def get_oauth_credentials(session_id: str = "default"):
    """
    Get and refresh OAuth user credentials for Google Analytics.
    
    This function implements a server-based OAuth flow:
    1. Checks for existing token file
    2. If token exists and valid, uses it
    3. If token expired, refreshes it
    4. If no token exists, creates Auth URL and stores flow for callback handler
    
    Args:
        session_id: Session identifier for multi-user support
        
    Returns:
        Credentials object ready to use
        
    Raises:
        RuntimeError: If authentication URL needs to be visited
        FileNotFoundError: If credentials path doesn't exist
    """
    creds = None
    
    if not GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH:
        raise ValueError(
            "GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH environment variable not set. "
            "Please set it to point to your OAuth credentials JSON file."
        )
    
    if not os.path.exists(GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH):
        raise FileNotFoundError(
            f"OAuth config file not found: {GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH}"
        )
    
    # Resolve actual session ID
    resolved_session_id = resolve_session_id(session_id)
    token_path = get_token_path(resolved_session_id)
    
    logger.info(f"Using session: {resolved_session_id}, token path: {token_path}")
    
    # Try to load existing token
    if os.path.exists(token_path):
        try:
            logger.info(f"Loading existing OAuth token from {token_path}")
            with open(token_path, "r") as f:
                creds_data = json.load(f)
            
            # Validate that this is a token file, not a config file
            if "installed" in creds_data or "web" in creds_data:
                raise RuntimeError(
                    f"Invalid token file at {token_path}. "
                    "This file contains OAuth client configuration. "
                    "Token file must contain ONLY access/refresh tokens."
                )
            
            creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
            logger.info("✓ Loaded existing token successfully")
            
        except json.JSONDecodeError as e:
            logger.error(f"Token file is corrupted: {e}")
            raise RuntimeError(
                f"Token file {token_path} is not valid JSON. "
                "Delete it and re-authenticate."
            )
        except Exception as e:
            logger.error(f"Failed to load token: {e}")
            raise
    
    # Check if credentials are valid
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Try to refresh
            try:
                logger.info("Token expired - attempting refresh")
                creds.refresh(Request())
                logger.info("✓ Token successfully refreshed")
                
                # Save refreshed token
                _save_credentials(token_path, creds)
                return creds
                
            except RefreshError as e:
                logger.error(f"Token refresh failed: {e}")
                raise RuntimeError(
                    "Stored credentials are invalid or revoked. "
                    "Delete the token file manually to re-authenticate."
                )
            except Exception as e:
                logger.error(f"Unexpected error refreshing token: {e}")
                raise
        
        # Need new authentication
        if not creds:
            logger.info("No valid token found - starting OAuth authentication flow")
            
            try:
                # Load client configuration
                with open(GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH, 'r') as f:
                    client_config = json.load(f)
                
                # Override redirect_uris with environment value
                if GOOGLE_GA4_REDIRECT_URI:
                    logger.info(f"Using redirect_uri from .env: {GOOGLE_GA4_REDIRECT_URI}")
                    client_config['web']['redirect_uris'] = [GOOGLE_GA4_REDIRECT_URI]
                
                # Create OAuth flow
                flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
                
                # CRITICAL: Set redirect_uri on the flow object
                if GOOGLE_GA4_REDIRECT_URI:
                    flow.redirect_uri = GOOGLE_GA4_REDIRECT_URI
                
                # Store flow for callback handler
                pending_auth_flows[resolved_session_id] = flow
                logger.info(f"Stored pending auth flow for session: {resolved_session_id}")
                
                # Generate authorization URL
                auth_url, state = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                    prompt='consent',
                    state=resolved_session_id
                )
                
                # Raise error with auth URL (will be caught by server)
                error_msg = (
                    f"\n\nAUTHENTICATION REQUIRED\n"
                    f"========================\n\n"
                    f"Please visit the following URL to authorize:\n\n"
                    f"{auth_url}\n\n"
                    f"After signing in, you will be redirected to:\n"
                    f"{GOOGLE_GA4_REDIRECT_URI}\n\n"
                    f"The server will capture the authorization code automatically.\n"
                    f"Try your request again after authentication is complete.\n"
                    f"========================\n"
                )
                logger.info(error_msg)
                raise RuntimeError(error_msg)
                
            except RuntimeError:
                raise
            except Exception as e:
                logger.error(f"OAuth flow creation failed: {e}")
                raise
    
    return creds


def _save_credentials(token_path: str, creds: Credentials):
    """
    Save credentials to disk.
    
    Args:
        token_path: Path to save the token file
        creds: Credentials object to save
    """
    try:
        logger.info(f"Saving credentials to {token_path}")
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        
        # Convert to JSON
        creds_data = json.loads(creds.to_json())
        
        # Preserve refresh_token if it exists in old file
        if os.path.exists(token_path):
            try:
                with open(token_path, "r") as f:
                    old_data = json.load(f)
                if "refresh_token" in old_data and "refresh_token" not in creds_data:
                    creds_data["refresh_token"] = old_data["refresh_token"]
            except Exception as e:
                logger.warning(f"Could not read old token file: {e}")
        
        # Write to file
        with open(token_path, "w") as f:
            json.dump(creds_data, f, indent=2)
        logger.info("✓ Credentials saved successfully")
        
    except Exception as e:
        logger.warning(f"Could not save credentials: {e}")


def get_headers_with_auto_token(session_id: str = "default") -> Dict[str, str]:
    """
    Get API headers with automatically managed token.
    
    This function will automatically trigger OAuth flow if needed.
    
    Args:
        session_id: Session identifier for multi-user support
        
    Returns:
        Dictionary with Authorization header
    """
    creds = get_oauth_credentials(session_id)
    
    headers = {
        'Authorization': f'Bearer {creds.token}',
        'Content-Type': 'application/json'
    }
    
    return headers


# OAuth Callback Handler (for Starlette/FastAPI app)
async def google_oauth_callback(request):
    """
    Handle OAuth 2.0 redirect from Google.
    
    This endpoint is registered as /callback on the MCP server.
    Google redirects here after user authorizes the application.
    
    Args:
        request: Starlette Request object
        
    Returns:
        HTML response with success/error message
    """
    from starlette.responses import Response
    
    logger.info("Received OAuth callback request")
    
    try:
        # Parse query parameters
        params = dict(request.query_params)
        code = params.get("code")
        error = params.get("error")
        state = params.get("state", "default")
        
        logger.info(f"Callback state: {state}, error: {error}, code_present: {bool(code)}")
        
        # Check for error from Google
        if error:
            logger.error(f"Google OAuth error: {error}")
            error_html = f"""
            <html>
            <head><title>Authorization Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: red;">✗ Authorization Failed</h1>
                <p>Google OAuth Error: <b>{error}</b></p>
                <p>Please try again.</p>
            </body>
            </html>
            """
            return Response(error_html, media_type="text/html", status_code=400)
        
        # Check for authorization code
        if not code:
            logger.error("No authorization code in callback")
            return Response(
                "Missing authorization code",
                status_code=400
            )
        
        # Retrieve the flow from pending_auth_flows
        flow = pending_auth_flows.get(state)
        if not flow:
            logger.error(f"Flow not found for state: {state}")
            error_html = f"""
            <html>
            <head><title>Session Not Found</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: red;">✗ Session Not Found</h1>
                <p>OAuth flow for session '<b>{state}</b>' not found.</p>
                <p>Please restart authentication and try again.</p>
            </body>
            </html>
            """
            return Response(error_html, media_type="text/html", status_code=500)
        
        try:
            # Exchange code for token
            logger.info(f"Exchanging code for token (session: {state})...")
            flow.fetch_token(code=code)
            creds = flow.credentials
            
            # Save credentials
            token_path = get_token_path(state)
            _save_credentials(token_path, creds)
            
            # Clean up
            if state in pending_auth_flows:
                del pending_auth_flows[state]
                logger.info(f"Cleaned up flow for session: {state}")
            
            # Return success HTML
            success_html = f"""
            <html>
            <head><title>Authorization Successful</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: green;">✓ Authorization Successful!</h1>
                <p>Session: <b>{state}</b></p>
                <p>You have successfully authorized the application.</p>
                <p>You can now close this window and return to Claude Desktop.</p>
                <p>Your request will be processed automatically.</p>
            </body>
            </html>
            """
            return Response(success_html, media_type="text/html", status_code=200)
        
        except Exception as e:
            logger.error(f"Error exchanging code for token: {e}")
            error_html = f"""
            <html>
            <head><title>Token Exchange Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: red;">✗ Token Exchange Failed</h1>
                <p>Error: {str(e)}</p>
                <p>Please try authentication again.</p>
            </body>
            </html>
            """
            return Response(error_html, media_type="text/html", status_code=500)
    
    except Exception as e:
        logger.error(f"Unexpected error in callback handler: {e}")
        from starlette.responses import Response
        return Response(
            f"Unexpected error: {str(e)}",
            status_code=500
        )


# Load active session on module import
load_active_session()