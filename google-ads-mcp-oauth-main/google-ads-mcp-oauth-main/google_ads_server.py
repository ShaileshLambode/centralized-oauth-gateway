from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging

# MCP
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.transport_security import TransportSecuritySettings

from mcp.server.auth.settings import AuthSettings
import time
import uvicorn
from starlette.responses import Response

# Global flow instance to hold state between generation and callback
# precise_mode: changes_global_state
# Global dictionary to hold pending auth flows: session_id -> flow_instance
pending_auth_flows: Dict[str, Any] = {}

# Global variable to track the currently active session ID
# precise_mode: changes_global_state
active_session_id: str = "default"

def get_config_path() -> Path:
    """Get the path to the configuration file."""
    # Store config next to the token path or in a standard location
    base_path = os.environ.get("GOOGLE_ADS_TOKEN_PATH", "google_ads_token.json")
    return Path(base_path).parent / "session_config.json"

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
    config_path = get_config_path()
    try:
        data = {"active_session_id": session_id}
        with open(config_path, "w") as f:
            json.dump(data, f)
        logger.info(f"Saved active session to config: {session_id}")
    except Exception as e:
        logger.warning(f"Failed to save session config: {str(e)}")

# Load active session on startup
load_active_session()


class TokenInfo:
    def __init__(
        self,
        sub: str,
        scopes: list[str],
        client_id: str,
        expires_at: int | None = None,
    ):
        self.sub = sub
        self.scopes = scopes
        self.client_id = client_id
        self.expires_at = expires_at

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

class AuthRequiredException(Exception):
    """Exception raised when user authentication is required."""
    pass

# Carica variabili d'ambiente dal file .env
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

mcp = FastMCP(
    "google_ads_mcp",
    host="0.0.0.0"
)

# Constants and configuration
# Relax token scope to allow extra scopes (like analytics) without error
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

SCOPES = [
    'https://www.googleapis.com/auth/adwords',
    'https://www.googleapis.com/auth/analytics',
    'https://www.googleapis.com/auth/analytics.readonly'
]
API_VERSION = "v19"  # Google Ads API version

# Load environment variables
try:
    from dotenv import load_dotenv
    # Load from .env file if it exists
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Get credentials from environment variables
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # oauth or service_account

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    # Convert to string if passed as integer or another type
    customer_id = str(customer_id)

    # Remove any quotes surrounding the customer_id (both escaped and unescaped)
    customer_id = customer_id.replace('\"', '').replace('"', '')

    # Remove any non-digit characters (including dashes, braces, etc.)
    customer_id = ''.join(char for char in customer_id if char.isdigit())

    # Ensure it's 10 digits with leading zeros if needed
    return customer_id.zfill(10)

def get_token_path(session_id: str) -> str:
    """Determine the token file path for a given session."""
    base_path = os.environ.get("GOOGLE_ADS_TOKEN_PATH", "google_ads_token.json")
    
    # Create tokens directory next to the base path
    p = Path(base_path)
    directory = p.parent / "tokens"
    directory.mkdir(exist_ok=True, parents=True)
    return str(directory / f"{session_id}.json")

def get_credentials(session_id: str = "default"):
    """
    Get and refresh OAuth credentials or service account credentials based on the auth type.

    This function supports two authentication methods:
    1. OAuth 2.0 (User Authentication) - For individual users or desktop applications
    2. Service Account (Server-to-Server Authentication) - For automated systems

    Returns:
        Valid credentials object to use with Google Ads API
    """
    # if not GOOGLE_ADS_CREDENTIALS_PATH:
    #     raise ValueError("GOOGLE_ADS_CREDENTIALS_PATH environment variable not set")

    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    
    # Resolve "default" to the active session ID
    if session_id == "default":
        global active_session_id
        session_id = active_session_id
        
    logger.info(f"Using authentication type: {auth_type} for session {session_id}")

    # Service Account authentication
    if auth_type == "service_account":
        if not GOOGLE_ADS_CREDENTIALS_PATH:
            raise ValueError(
                "GOOGLE_ADS_CREDENTIALS_PATH must be set for service_account authentication"
            )
        return get_service_account_credentials()

    # OAuth path (default)
    return get_oauth_credentials(session_id)


def get_service_account_credentials():
    """Get credentials using a service account key file."""
    logger.info(f"Loading service account credentials from {GOOGLE_ADS_CREDENTIALS_PATH}")

    if not os.path.exists(GOOGLE_ADS_CREDENTIALS_PATH):
        raise FileNotFoundError(f"Service account key file not found at {GOOGLE_ADS_CREDENTIALS_PATH}")

    try:
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_ADS_CREDENTIALS_PATH,
            scopes=SCOPES
        )

        # Check if impersonation is required
        impersonation_email = os.environ.get("GOOGLE_ADS_IMPERSONATION_EMAIL")
        if impersonation_email:
            logger.info(f"Impersonating user: {impersonation_email}")
            credentials = credentials.with_subject(impersonation_email)

        return credentials

    except Exception as e:
        logger.error(f"Error loading service account credentials: {str(e)}")
        raise

def get_oauth_credentials(session_id: str):
    """Get and refresh OAuth user credentials."""
    creds = None
    client_config = None

    # Determine token path based on session_id
    token_path = get_token_path(session_id)

    # Check if token file exists and load credentials
    if os.path.exists(token_path):
        try:
            logger.info(f"Loading OAuth token from {token_path}")
            with open(token_path, "r") as f:
                creds_data = json.load(f)

            # HARD FAIL if token file contains client config
            if "installed" in creds_data or "web" in creds_data:
                raise RuntimeError(
                    f"Invalid token file at {token_path}. "
                    "This file contains OAuth client configuration. "
                    "Token file must contain ONLY access/refresh tokens."
                )

            logger.info("Found existing OAuth token")
            try:
                creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
            except ValueError as e:
                # This specific error usually means 'missing fields refresh_token'
                logger.warning(f"Cached token is invalid (missing fields): {e}")
                logger.info(f"Deleting invalid token file: {token_path}")
                os.remove(token_path)
                creds = None

        except json.JSONDecodeError:
            logger.warning(f"Token file {token_path} is not valid JSON. Deleting it.")
            os.remove(token_path)
            creds = None
            
        except Exception as e:
            # If we can't recover, re-raise
            raise RuntimeError(f"Failed to load OAuth token: {str(e)}")


    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.info("Refreshing expired token")
                creds.refresh(Request())
                logger.info("Token successfully refreshed")
            except RefreshError as e:
                raise RuntimeError("Stored credentials are invalid or revoked. ""Delete creds.json manually to re-authenticate.")

            except Exception as e:
                logger.error(f"Unexpected error refreshing token: {str(e)}")
                raise

        # OAuth is allowed ONLY if token file does not exist
        if not creds:
            client_secret_path = os.environ.get("GOOGLE_ADS_CLIENT_SECRET_PATH")

            if not client_secret_path or not os.path.exists(client_secret_path):
                raise RuntimeError(
                    "OAuth token not found and client_secret.json is missing. "
                    "Provide GOOGLE_ADS_CLIENT_SECRET_PATH to authenticate."
                )

            logger.info("No OAuth token found — starting ONE-TIME OAuth login")

            # Check if using a specific redirect URI (e.g. for remote/headless)
            redirect_uri = os.environ.get("GOOGLE_ADS_REDIRECT_URI")
            
            if redirect_uri:
                logger.info(f"Using manual/server OAuth flow with redirect_uri: {redirect_uri}")
                
                # Make flow global state available for callback
                # We use the session_id as the OAuth 'state' parameter
                flow = InstalledAppFlow.from_client_secrets_file(
                    client_secret_path,
                    SCOPES,
                    redirect_uri=redirect_uri
                )
                
                # Store flow in pending_auth_flows using the session_id (which is also the state)
                pending_auth_flows[session_id] = flow
                
                auth_url, _ = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true',
                    prompt='consent',
                    state=session_id
                )
                
                # Raise a specific exception that tools can catch and return cleanly
                raise AuthRequiredException(
                    f"AUTHENTICATION REQUIRED\n"
                    f"--------------------------------------------------\n"
                    f"Please visit the following URL to authenticate:\n"
                    f"{auth_url}\n"
                    f"--------------------------------------------------\n"
                    f"After signing in, you will be redirected to: {redirect_uri}\n"
                    f"The server will capture the token automatically.\n"
                    f"Try your request again after authentication is complete."
                )
            
            else:
                # Default "local" behavior (opens browser on server machine)
                logger.info("No redirect URI configured — attempting local browser flow")
                flow = InstalledAppFlow.from_client_secrets_file(
                    client_secret_path,
                    SCOPES
                )

                creds = flow.run_local_server(
                    port=8080,
                    access_type="offline",
                    prompt="consent"
                )

            logger.info("OAuth flow completed successfully")


        # Save the refreshed/new credentials
        try:
            logger.info(f"Saving credentials to {token_path}")
            # Ensure directory exists
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            data = json.loads(creds.to_json())
            if os.path.exists(token_path):
                with open(token_path, "r") as f:
                    old = json.load(f)

                if "refresh_token" in old and "refresh_token" not in data:
                    data["refresh_token"] = old["refresh_token"]

            with open(token_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save credentials: {str(e)}")

    return creds

def get_headers(creds):
    """Get headers for Google Ads API requests."""
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")

    # Handle different credential types
    if isinstance(creds, service_account.Credentials):
        # For service account, we need to get a new bearer token
        auth_req = Request()
        creds.refresh(auth_req)
        token = creds.token
    else:
        # For OAuth credentials, check if token needs refresh
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                try:
                    logger.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                    logger.info("Token successfully refreshed in get_headers")
                except RefreshError as e:
                    logger.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error refreshing token in get_headers: {str(e)}")
                    raise
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")

        token = creds.token

    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }

    if GOOGLE_ADS_LOGIN_CUSTOMER_ID:
        headers['login-customer-id'] = format_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)

    return headers

# @mcp.tool()
# async def list_accounts() -> str:
#     """
#     Lists all accessible Google Ads accounts.

#     This is typically the first command you should run to identify which accounts
#     you have access to. The returned account IDs can be used in subsequent commands.

#     Returns:
#         A formatted list of all Google Ads accounts accessible with your credentials
#     """
#     try:
#         target_session_id = resolve_session_id(ctx, session_id)
#         logger.info(f"Resolving credentials for session: {target_session_id}")
#         creds = get_credentials(target_session_id)
#         headers = get_headers(creds)

#         url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
#         response = requests.get(url, headers=headers)

#         if response.status_code != 200:
#             return f"Error accessing accounts: {response.text}"

#         customers = response.json()
#         if not customers.get('resourceNames'):
#             return "No accessible accounts found."

#         # Format the results
#         result_lines = ["Accessible Google Ads Accounts:"]
#         result_lines.append("-" * 50)

#         for resource_name in customers['resourceNames']:
#             customer_id = resource_name.split('/')[-1]
#             formatted_id = format_customer_id(customer_id)
#             result_lines.append(f"Account ID: {formatted_id}")

#         return "\n".join(result_lines)

#     except Exception as e:
#         return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def set_active_session(session_id: str = Field(description="The session ID to make active")) -> str:
    """
    Set the active session ID for all subsequent operations.
    
    This allows you to switch between different user sessions. 
    Once set, all tools will use this session ID by default unless explicitly overridden.
    
    Args:
        session_id: The session ID to activate (e.g., 'user_1', 'project_alpha')
        
    Returns:
        Confirmation message
    """
    global active_session_id
    active_session_id = session_id
    save_active_session(session_id)
    logger.info(f"Active session changed to: {active_session_id}")
    return f"Active session set to: {active_session_id}"

@mcp.tool()
async def get_active_session() -> str:
    """
    Get the currently active session ID.
    
    Returns:
        The current session ID
    """
    return f"Current active session: {active_session_id}"

def resolve_session_id(ctx: Context, session_id: str) -> str:
    """
    Resolve the effective session ID.
    Priority: Explicit Session ID > Sticky Session > Transport Session > "default"
    """
    # 1. Explicit session_id passed by user (if not default)
    if session_id != "default":
        return session_id

    # 2. Sticky Session (if set)
    global active_session_id
    if active_session_id != "default":
        return active_session_id

    # 3. Transport Session (from connection)
    # Strategy: Extract from mcp-session-id header
    if hasattr(ctx, 'request_context'):
        rc = ctx.request_context
        if hasattr(rc, 'request') and hasattr(rc.request, 'headers'):
            headers = rc.request.headers
            if 'mcp-session-id' in headers:
                sid = headers['mcp-session-id']
                logger.info(f"Resolved Transport Session ID from header: {sid}")
                return sid

    # 4. Fallback
    return "default"

@mcp.tool()
async def list_accounts(
    ctx: Context,
    session_id: str = Field(default="default", description="Session ID for multi-user support (default: 'default')")
) -> str:
    """
    Lists all client (non-manager) Google Ads accounts under all accessible managers.
    """
    try:
        target_session_id = resolve_session_id(ctx, session_id)
        logger.info(f"Resolving credentials for session: {target_session_id}")
        
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)

        # Step 1: get accessible customers (mostly MCCs)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

        managers = resp.json().get("resourceNames", [])
        if not managers:
            return "No accessible manager accounts found."

        results = ["All Client Accounts", "-" * 50]

        # Step 2: for each manager, fetch customer_client tree
        for resource in managers:
            manager_id = resource.split("/")[-1]

            query = """
                SELECT
                customer_client.id,
                customer_client.descriptive_name,
                customer_client.manager,
                customer_client.level,
                customer_client.status
                FROM customer_client
            """


            search_url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{manager_id}/googleAds:search"

            manager_headers = headers.copy()
            manager_headers["login-customer-id"] = manager_id

            r = requests.post(
                search_url,
                headers=manager_headers,
                json={"query": query}
            )

            if r.status_code != 200:
                results.append(f"\nManager {manager_id}: ERROR {r.text}")
                continue

            rows = r.json().get("results", [])

            results.append(f"\nManager Account: {format_customer_id(manager_id)}")

            for row in rows:
                cc = row["customerClient"]

                # Only real client accounts (not managers)
                if not cc["manager"]:
                    results.append(
                        f"  - Customer ID: {format_customer_id(cc['id'])} | "
                        f"Name: {cc.get('descriptiveName', 'N/A')}"
                    )

        return "\n".join(results)

    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error listing client accounts: {str(e)}"

#--> NEW ADDED "Resolve Customer"
@mcp.tool()
async def resolve_customer(
    ctx: Context,
    customer: str = Field(description="Customer name or customer ID"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Resolve a customer name or ID into a valid Google Ads customer ID.
    """
    target_session_id = resolve_session_id(ctx, session_id)
    # Case 1: already looks like an ID
    digits = ''.join(c for c in customer if c.isdigit())
    if len(digits) == 10:
        return format_customer_id(digits)


    # Case 2: treat as name
    accounts = await list_accounts(ctx=ctx, session_id=target_session_id)
    
    # Propagate authentication requests
    if "AUTHENTICATION REQUIRED" in accounts:
        return accounts

    matches = []

    for line in accounts.splitlines():
        if "Customer ID:" in line and "Name:" in line:
            parts = line.split("|")
            cid = parts[0].split(":")[-1].strip()
            name = parts[1].split(":")[-1].strip()

            if customer.lower() in name.lower():
                matches.append((cid, name))

    if not matches:
        return f"❌ No customer found matching '{customer}'"

    if len(matches) > 1:
        return f"⚠️ Multiple customers matched '{customer}'"

    return matches[0][0]

#--> NEW ADDED "CENTRAL ANALYTICS ROUTER"

@mcp.tool()
async def analytics_router(
    ctx: Context,
    customer: str = Field(description="Customer name or customer ID"),
    intent: str = Field(description="What to analyze: campaigns, ads, creatives, images, asset_usage"),
    days: int = Field(default=30, description="Lookback window in days (7, 14, 30, 90)"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Central router that:
    - Resolves customer name → customer_id
    - Builds safe GAQL queries
    - Executes analytics in ONE step
    """

    target_session_id = resolve_session_id(ctx, session_id)
    # 1️⃣ Resolve customer
    customer_id = await resolve_customer(ctx=ctx, customer=customer, session_id=target_session_id)
    if not customer_id.isdigit():
        return customer_id

    # 2️⃣ Normalize intent
    intent = intent.lower().strip()
    if not intent:
        intent = "campaigns"


    # 3️⃣ Normalize date range
    if days in (7, 14, 30, 90):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    # 4️⃣ Route intent → GAQL
    if intent in ("campaign", "campaigns", "campaign performance"):
        query = f"""
            SELECT
                campaign.id,
                campaign.name,
                campaign.status,
                metrics.impressions,
                metrics.clicks,
                metrics.cost_micros,
                metrics.conversions,
                metrics.average_cpc
            FROM campaign
            WHERE segments.date DURING {date_range}
            ORDER BY metrics.cost_micros DESC
            LIMIT 50
        """
        return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

    if intent in ("ad", "ads", "ad performance"):
        query = f"""
            SELECT
                ad_group_ad.ad.id,
                ad_group_ad.ad.name,
                ad_group_ad.status,
                campaign.name,
                ad_group.name,
                metrics.impressions,
                metrics.clicks,
                metrics.cost_micros,
                metrics.conversions
            FROM ad_group_ad
            WHERE segments.date DURING {date_range}
            ORDER BY metrics.impressions DESC
            LIMIT 50
        """
        return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

    if intent in ("creative", "creatives", "ad creatives"):
        query = """
            SELECT
                ad_group_ad.ad.id,
                ad_group_ad.ad.name,
                ad_group_ad.ad.type,
                ad_group_ad.ad.final_urls,
                campaign.name,
                ad_group.name
            FROM ad_group_ad
            WHERE ad_group_ad.status != 'REMOVED'
            LIMIT 50
        """
        return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

    if intent in (
    "image", "images", "image asset", "image assets",
    "image_assets", "assets", "asset images"
):

        query = """
            SELECT
                asset.id,
                asset.name,
                asset.image_asset.full_size.url,
                asset.image_asset.full_size.width_pixels,
                asset.image_asset.full_size.height_pixels
            FROM asset
            WHERE asset.type = 'IMAGE'
            LIMIT 50
        """
        return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

    if intent in (
    "asset_usage", "asset usage", "usage", "asset use", "asset mapping"
):

        query = """
            SELECT
                campaign.name,
                asset.id,
                asset.name
            FROM campaign_asset
            LIMIT 100
        """
        return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

    return (
        "❌ Unknown intent.\n"
        "Valid intents:\n"
        "- campaigns\n"
        "- ads\n"
        "- creatives\n"
        "- images\n"
        "- asset_usage"
    )

@mcp.tool()
async def execute_gaql_query(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Execute a custom GAQL (Google Ads Query Language) query.
    
    This tool allows you to run any valid GAQL query against the Google Ads API.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        query: The GAQL query to execute (must follow GAQL syntax)
        session_id: The session ID for multi-user support
        
    Returns:
        Formatted query results or error message
        
    Example:
        customer_id: "1234567890"
        query: "SELECT campaign.id, campaign.name FROM campaign LIMIT 10"
    """
    try:
        target_session_id = resolve_session_id(ctx, session_id)
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        # Format the results as a table
        result_lines = [f"Query Results for Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        # Get field names from the first result
        fields = []
        first_result = results['results'][0]
        for key in first_result:
            if isinstance(first_result[key], dict):
                for subkey in first_result[key]:
                    fields.append(f"{key}.{subkey}")
            else:
                fields.append(key)
        
        # Add header
        result_lines.append(" | ".join(fields))
        result_lines.append("-" * 80)
        
        # Add data rows
        for result in results['results']:
            row_data = []
            for field in fields:
                if "." in field:
                    parent, child = field.split(".")
                    value = str(result.get(parent, {}).get(child, ""))
                else:
                    value = str(result.get(field, ""))
                row_data.append(value)
            result_lines.append(" | ".join(row_data))
        
        return "\n".join(result_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Get campaign performance metrics for the specified time period.
    
    NOTE:
    This tool is INTERNAL.
    Prefer `analytics_router` unless the user explicitly provides a customer_id.

    Retrieves campaign performance metrics.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Formatted table of campaign performance data
        
    Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.average_cpc
        FROM campaign
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.cost_micros DESC
        LIMIT 50
    """
    return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

@mcp.tool()
async def get_ad_performance(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Get ad performance metrics for the specified time period.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Formatted table of ad performance data
        
    Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = f"""
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.status,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group_ad
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 50
    """
    
    return await execute_gaql_query(ctx=ctx, customer_id=customer_id, query=query, session_id=target_session_id)

@mcp.tool()
async def run_gaql(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Execute any arbitrary GAQL (Google Ads Query Language) query with custom formatting options.
    
    This is the most powerful tool for custom Google Ads data queries.
    
    NOTE:
    This tool is INTERNAL.
    Prefer `analytics_router` unless the user explicitly provides a customer_id.

    Run a custom GAQL query.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        query: The GAQL query to execute (any valid GAQL query)
        format: Output format ("table", "json", or "csv")
    
    Returns:
        Query results in the requested format
    
    EXAMPLE QUERIES:
    
    1. Basic campaign metrics:
        SELECT 
          campaign.name, 
          metrics.clicks, 
          metrics.impressions,
          metrics.cost_micros
        FROM campaign 
        WHERE segments.date DURING LAST_7_DAYS
    
    2. Ad group performance:
        SELECT 
          ad_group.name, 
          metrics.conversions, 
          metrics.cost_micros,
          campaign.name
        FROM ad_group 
        WHERE metrics.clicks > 100
    
    3. Keyword analysis:
        SELECT 
          keyword.text, 
          metrics.average_position, 
          metrics.ctr
        FROM keyword_view 
        ORDER BY metrics.impressions DESC
        
    4. Get conversion data:
        SELECT
          campaign.name,
          metrics.conversions,
          metrics.conversions_value,
          metrics.cost_micros
        FROM campaign
        WHERE segments.date DURING LAST_30_DAYS
        
            Note:
        Cost values are in micros (millionths) of the account currency
        (e.g., 1000000 = 1 USD in a USD account)
    """
    try:
        target_session_id = resolve_session_id(ctx, session_id)
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        if format.lower() == "json":
            return json.dumps(results, indent=2)
        
        elif format.lower() == "csv":
            # Get field names from the first result
            fields = []
            first_result = results['results'][0]
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        fields.append(f"{key}.{subkey}")
                else:
                    fields.append(key)
            
            # Create CSV string
            csv_lines = [",".join(fields)]
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, "")).replace(",", ";")
                    else:
                        value = str(result.get(field, "")).replace(",", ";")
                    row_data.append(value)
                csv_lines.append(",".join(row_data))
            
            return "\n".join(csv_lines)
        
        else:  # default table format
            result_lines = [f"Query Results for Account {formatted_customer_id}:"]
            result_lines.append("-" * 100)
            
            # Get field names and maximum widths
            fields = []
            field_widths = {}
            first_result = results['results'][0]
            
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        field = f"{key}.{subkey}"
                        fields.append(field)
                        field_widths[field] = len(field)
                else:
                    fields.append(key)
                    field_widths[key] = len(key)
            
            # Calculate maximum field widths
            for result in results['results']:
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    field_widths[field] = max(field_widths[field], len(value))
            
            # Create formatted header
            header = " | ".join(f"{field:{field_widths[field]}}" for field in fields)
            result_lines.append(header)
            result_lines.append("-" * len(header))
            
            # Add data rows
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    row_data.append(f"{value:{field_widths[field]}}")
                result_lines.append(" | ".join(row_data))
            
            return "\n".join(result_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_ad_creatives(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Get ad creative details including headlines, descriptions, and URLs.
    
    This tool retrieves the actual ad content (headlines, descriptions) 
    for review and analysis. Great for creative audits.
    
    NOTE:
        This tool is INTERNAL.
        Prefer `analytics_router` unless the user explicitly provides a customer_id.

    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        
    Returns:
        Formatted list of ad creative details
        
    Example:
        customer_id: "1234567890"
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = """
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.ad.type,
            ad_group_ad.ad.final_urls,
            ad_group_ad.status,
            ad_group_ad.ad.responsive_search_ad.headlines,
            ad_group_ad.ad.responsive_search_ad.descriptions,
            ad_group.name,
            campaign.name
        FROM ad_group_ad
        WHERE ad_group_ad.status != 'REMOVED'
        ORDER BY campaign.name, ad_group.name
        LIMIT 50
    """
    
    try:
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving ad creatives: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No ad creatives found for this customer ID."
        
        # Format the results in a readable way
        output_lines = [f"Ad Creatives for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            ad = result.get('adGroupAd', {}).get('ad', {})
            ad_group = result.get('adGroup', {})
            campaign = result.get('campaign', {})
            
            output_lines.append(f"\n{i}. Campaign: {campaign.get('name', 'N/A')}")
            output_lines.append(f"   Ad Group: {ad_group.get('name', 'N/A')}")
            output_lines.append(f"   Ad ID: {ad.get('id', 'N/A')}")
            output_lines.append(f"   Ad Name: {ad.get('name', 'N/A')}")
            output_lines.append(f"   Status: {result.get('adGroupAd', {}).get('status', 'N/A')}")
            output_lines.append(f"   Type: {ad.get('type', 'N/A')}")
            
            # Handle Responsive Search Ads
            rsa = ad.get('responsiveSearchAd', {})
            if rsa:
                if 'headlines' in rsa:
                    output_lines.append("   Headlines:")
                    for headline in rsa['headlines']:
                        output_lines.append(f"     - {headline.get('text', 'N/A')}")
                
                if 'descriptions' in rsa:
                    output_lines.append("   Descriptions:")
                    for desc in rsa['descriptions']:
                        output_lines.append(f"     - {desc.get('text', 'N/A')}")
            
            # Handle Final URLs
            final_urls = ad.get('finalUrls', [])
            if final_urls:
                output_lines.append(f"   Final URLs: {', '.join(final_urls)}")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Retrieve the default currency code used by the Google Ads account.
    
    IMPORTANT: Run this first before analyzing cost data to understand which currency
    the account uses. Cost values are always displayed in the account's currency.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
    
    Returns:
        The account's default currency code (e.g., 'USD', 'EUR', 'GBP')
        
    Example:
        customer_id: "1234567890"
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    
    try:
        creds = get_credentials(target_session_id)
        
        # Force refresh if needed
        if not creds.valid:
            logger.info("Credentials not valid, attempting refresh...")
            if hasattr(creds, 'refresh_token') and creds.refresh_token:
                creds.refresh(Request())
                logger.info("Credentials refreshed successfully")
            else:
                raise ValueError("Invalid credentials and no refresh token available")
        
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving account currency: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer ID."
        
        # Extract the currency code from the results
        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        
        return f"Account {formatted_customer_id} uses currency: {currency_code}"
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    """Google Ads Query Language (GAQL) reference documentation."""
    return """
    # Google Ads Query Language (GAQL) Reference
    
    GAQL is similar to SQL but with specific syntax for Google Ads. Here's a quick reference:
    
    ## Basic Query Structure
    ```
    SELECT field1, field2, ... 
    FROM resource_type
    WHERE condition
    ORDER BY field [ASC|DESC]
    LIMIT n
    ```
    
    ## Common Field Types
    
    ### Resource Fields
    - campaign.id, campaign.name, campaign.status
    - ad_group.id, ad_group.name, ad_group.status
    - ad_group_ad.ad.id, ad_group_ad.ad.final_urls
    - keyword.text, keyword.match_type
    
    ### Metric Fields
    - metrics.impressions
    - metrics.clicks
    - metrics.cost_micros
    - metrics.conversions
    - metrics.ctr
    - metrics.average_cpc
    
    ### Segment Fields
    - segments.date
    - segments.device
    - segments.day_of_week
    
    ## Common WHERE Clauses
    
    ### Date Ranges
    - WHERE segments.date DURING LAST_7_DAYS
    - WHERE segments.date DURING LAST_30_DAYS
    - WHERE segments.date BETWEEN '2023-01-01' AND '2023-01-31'
    
    ### Filtering
    - WHERE campaign.status = 'ENABLED'
    - WHERE metrics.clicks > 100
    - WHERE campaign.name LIKE '%Brand%'
    
    ## Tips
    - Always check account currency before analyzing cost data
    - Cost values are in micros (millionths): 1000000 = 1 unit of currency
    - Use LIMIT to avoid large result sets
    """
@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    """Enforces the single-entry Central Router workflow for Google Ads analytics."""
    return """
    You are an execution agent for Google Ads analytics.

    =========================
    CRITICAL EXECUTION RULES
    =========================

    1. If the user asks for ANY Google Ads data, analytics, performance, creatives, images, or assets,
       you MUST call the `analytics_router` tool.
       - You are NOT allowed to answer from context.
       - You are NOT allowed to say “data is not available” without calling a tool.
       - You are NOT allowed to ask follow-up questions before calling a tool.

    2. NEVER attempt to manually infer or remember a customer_id from conversation history.
       - Customer resolution MUST happen inside `analytics_router`.

    3. NEVER call ID-based tools directly unless:
       - The user explicitly provides a `customer_id` in their message.

    4. ONE user request = ONE tool call.
       - Do NOT split work across multiple messages.
       - Do NOT rely on previous turns.

    =========================
    REQUIRED WORKFLOW
    =========================

    - Use `analytics_router` as the ONLY entry point for all analytics requests.
    - This tool is responsible for:
        • Resolving customer name → customer_id
        • Determining analytics intent
        • Executing the correct GAQL query
        • Returning results in a single step

    =========================
    WHEN TO USE OTHER TOOLS
    =========================

    - Use `get_account_hierarchy()` ONLY if the user explicitly asks to list available accounts.
    - Use ID-based tools ONLY if the user explicitly provides a customer_id, for example:
        • get_campaign_performance(customer_id="1234567890")
        • get_ad_performance(customer_id="1234567890")
        • run_gaql(customer_id="1234567890", query="...")

    =========================
    INTENT MAPPING (REFERENCE)
    =========================

    - campaigns     → campaign performance
    - ads           → ad-level performance
    - creatives     → ad creatives
    - images        → image assets
    - asset_usage   → asset usage mapping

    =========================
    NON-NEGOTIABLE RULE
    =========================

    If analytics data is requested and you do not call `analytics_router`,
    the response is considered INVALID.

    Always execute. Never assume. Never answer from context.
    """



@mcp.prompt("gaql_help")
def gaql_help() -> str:
    """Provides assistance for writing GAQL queries."""
    return """
    I'll help you write a Google Ads Query Language (GAQL) query. Here are some examples to get you started:
    
    ## Get campaign performance last 30 days
    ```
    SELECT
      campaign.id,
      campaign.name,
      campaign.status,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions
    FROM campaign
    WHERE segments.date DURING LAST_30_DAYS
    ORDER BY metrics.cost_micros DESC
    ```
    
    ## Get keyword performance
    ```
    SELECT
      keyword.text,
      keyword.match_type,
      metrics.impressions,
      metrics.clicks,
      metrics.cost_micros,
      metrics.conversions
    FROM keyword_view
    WHERE segments.date DURING LAST_30_DAYS
    ORDER BY metrics.clicks DESC
    ```
    
    ## Get ads with poor performance
    ```
    SELECT
      ad_group_ad.ad.id,
      ad_group_ad.ad.name,
      campaign.name,
      ad_group.name,
      metrics.impressions,
      metrics.clicks,
      metrics.conversions
    FROM ad_group_ad
    WHERE 
      segments.date DURING LAST_30_DAYS
      AND metrics.impressions > 1000
      AND metrics.ctr < 0.01
    ORDER BY metrics.impressions DESC
    ```
    
    Once you've chosen a query, use it with:
    ```
    run_gaql(customer_id="YOUR_ACCOUNT_ID", query="YOUR_QUERY_HERE")
    ```
    
    Remember:
    - Always provide the customer_id as a string
    - Cost values are in micros (1,000,000 = 1 unit of currency)
    - Use LIMIT to avoid large result sets
    - Check the account currency before analyzing cost data
    """

@mcp.tool()
async def get_image_assets(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    limit: int = Field(default=50, description="Maximum number of image assets to return"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Retrieve all image assets in the account including their full-size URLs.
    
    This tool allows you to get details about image assets used in your Google Ads account,
    including the URLs to download the full-size images for further processing or analysis.
    
    NOTE:
        This tool is INTERNAL.
        Prefer `analytics_router` unless the user explicitly provides a customer_id.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        limit: Maximum number of image assets to return (default: 50)
        
    Returns:
        Formatted list of image assets with their download URLs
        
    Example:
        customer_id: "1234567890"
        limit: 100
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
        LIMIT {limit}
    """
    
    try:
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image assets found for this customer ID."
        
        # Format the results in a readable way
        output_lines = [f"Image Assets for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            asset = result.get('asset', {})
            image_asset = asset.get('imageAsset', {})
            full_size = image_asset.get('fullSize', {})
            
            output_lines.append(f"\n{i}. Asset ID: {asset.get('id', 'N/A')}")
            output_lines.append(f"   Name: {asset.get('name', 'N/A')}")
            
            if full_size:
                output_lines.append(f"   Image URL: {full_size.get('url', 'N/A')}")
                output_lines.append(f"   Dimensions: {full_size.get('widthPixels', 'N/A')} x {full_size.get('heightPixels', 'N/A')} px")
            
            file_size = image_asset.get('fileSize', 'N/A')
            if file_size != 'N/A':
                # Convert to KB for readability
                file_size_kb = int(file_size) / 1024
                output_lines.append(f"   File Size: {file_size_kb:.2f} KB")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def download_image_asset(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Download a specific image asset from a Google Ads account.
    
    This tool allows you to download the full-size version of an image asset
    for further processing, analysis, or backup.
    
    NOTE:
        This tool is INTERNAL.
        Prefer `analytics_router` unless the user explicitly provides a customer_id.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: The ID of the image asset to download
        output_dir: Directory where the image should be saved (default: ./ad_images)
        
    Returns:
        Status message indicating success or failure of the download
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        output_dir: "./my_ad_images"
    """
    target_session_id = resolve_session_id(ctx, session_id)
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
            AND asset.id = {asset_id}
        LIMIT 1
    """
    
    try:
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image asset: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"
        
        # Extract the image URL
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"
        
        # Validate and sanitize the output directory to prevent path traversal
        try:
            # Get the base directory (current working directory)
            base_dir = Path.cwd()
            # Resolve the output directory to an absolute path
            resolved_output_dir = Path(output_dir).resolve()
            
            # Ensure the resolved path is within or under the current working directory
            # This prevents path traversal attacks like "../../../etc"
            try:
                resolved_output_dir.relative_to(base_dir)
            except ValueError:
                # If the path is not relative to base_dir, use the default safe directory
                resolved_output_dir = base_dir / "ad_images"
                logger.warning(f"Invalid output directory '{output_dir}' - using default './ad_images'")
            
            # Create output directory if it doesn't exist
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            return f"Error creating output directory: {str(e)}"
        
        # Download the image
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        # Clean the filename to be safe for filesystem
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = resolved_output_dir / filename
        
        # Save the image
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"Successfully downloaded image asset {asset_id} to {file_path}"
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(default=None, description="Optional: specific asset ID to look up (leave empty to get all image assets)"),
    asset_type: str = Field(default="IMAGE", description="Asset type to search for ('IMAGE', 'TEXT', 'VIDEO', etc.)"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Find where specific assets are being used in campaigns, ad groups, and ads.
    
    This tool helps you analyze how assets are linked to campaigns and ads across your account,
    which is useful for creative analysis and optimization.
    
    NOTE:
        This tool is INTERNAL.
        Prefer `analytics_router` unless the user explicitly provides a customer_id.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: Optional specific asset ID to look up (leave empty to get all assets of the specified type)
        asset_type: Type of asset to search for (default: 'IMAGE')
        
    Returns:
        Formatted report showing where assets are used in the account
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        asset_type: "IMAGE"
    """
    target_session_id = resolve_session_id(ctx, session_id)
    # Build the query based on whether a specific asset ID was provided
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"
    
    # First get the assets themselves
    assets_query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type
        FROM
            asset
        WHERE
            {where_clause}
        LIMIT 100
    """
    
    # Then get the associations between assets and campaigns/ad groups
    # Try using campaign_asset instead of asset_link
    associations_query = f"""
        SELECT
            campaign.id,
            campaign.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            campaign_asset
        WHERE
            {where_clause}
        LIMIT 500
    """

    # Also try ad_group_asset for ad group level information
    ad_group_query = f"""
        SELECT
            ad_group.id,
            ad_group.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            ad_group_asset
        WHERE
            {where_clause}
        LIMIT 500
    """
    
    try:
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        
        # First get the assets
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        payload = {"query": assets_query}
        assets_response = requests.post(url, headers=headers, json=payload)
        
        if assets_response.status_code != 200:
            return f"Error retrieving assets: {assets_response.text}"
        
        assets_results = assets_response.json()
        if not assets_results.get('results'):
            return f"No {asset_type} assets found for this customer ID."
        
        # Now get the associations
        payload = {"query": associations_query}
        assoc_response = requests.post(url, headers=headers, json=payload)
        
        if assoc_response.status_code != 200:
            return f"Error retrieving asset associations: {assoc_response.text}"
        
        assoc_results = assoc_response.json()
        
        # Format the results in a readable way
        output_lines = [f"Asset Usage for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        # Create a dictionary to organize asset usage by asset ID
        asset_usage = {}
        
        # Initialize the asset usage dictionary with basic asset info
        for result in assets_results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            if asset_id:
                asset_usage[asset_id] = {
                    'name': asset.get('name', 'Unnamed asset'),
                    'type': asset.get('type', 'Unknown'),
                    'usage': []
                }
        
        # Add usage information from the associations
        for result in assoc_results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            
            if asset_id and asset_id in asset_usage:
                campaign = result.get('campaign', {})
                ad_group = result.get('adGroup', {})
                ad = result.get('adGroupAd', {}).get('ad', {}) if 'adGroupAd' in result else {}
                asset_link = result.get('assetLink', {})
                
                usage_info = {
                    'campaign_id': campaign.get('id', 'N/A'),
                    'campaign_name': campaign.get('name', 'N/A'),
                    'ad_group_id': ad_group.get('id', 'N/A'),
                    'ad_group_name': ad_group.get('name', 'N/A'),
                    'ad_id': ad.get('id', 'N/A') if ad else 'N/A',
                    'ad_name': ad.get('name', 'N/A') if ad else 'N/A'
                }
                
                asset_usage[asset_id]['usage'].append(usage_info)
        
        # Format the output
        for asset_id, info in asset_usage.items():
            output_lines.append(f"\nAsset ID: {asset_id}")
            output_lines.append(f"Name: {info['name']}")
            output_lines.append(f"Type: {info['type']}")
            
            if info['usage']:
                output_lines.append("\nUsed in:")
                output_lines.append("-" * 60)
                output_lines.append(f"{'Campaign':<30} | {'Ad Group':<30}")
                output_lines.append("-" * 60)
                
                for usage in info['usage']:
                    campaign_str = f"{usage['campaign_name']} ({usage['campaign_id']})"
                    ad_group_str = f"{usage['ad_group_name']} ({usage['ad_group_id']})"
                    
                    output_lines.append(f"{campaign_str[:30]:<30} | {ad_group_str[:30]:<30}")
            
            output_lines.append("=" * 80)
        
        return "\n".join(output_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error retrieving asset usage: {str(e)}"

@mcp.tool()
async def analyze_image_assets(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    Analyze image assets with their performance metrics across campaigns.
    
    This comprehensive tool helps you understand which image assets are performing well
    by showing metrics like impressions, clicks, and conversions for each image.
    
    NOTE:
        This tool is INTERNAL.
        Prefer `analytics_router` unless the user explicitly provides a customer_id.

    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        
    Returns:
        Detailed report of image assets and their performance metrics
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
    target_session_id = resolve_session_id(ctx, session_id)
    # Make sure to use a valid date range format
    # Valid formats are: LAST_7_DAYS, LAST_14_DAYS, LAST_30_DAYS, etc. (with underscores)
    if days == 7:
        date_range = "LAST_7_DAYS"
    elif days == 14:
        date_range = "LAST_14_DAYS"
    elif days == 30:
        date_range = "LAST_30_DAYS"
    else:
        # Default to 30 days if not a standard range
        date_range = "LAST_30_DAYS"
        
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.full_size.height_pixels,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.conversions,
            metrics.cost_micros
        FROM
            campaign_asset
        WHERE
            asset.type = 'IMAGE'
            AND segments.date DURING LAST_30_DAYS
        ORDER BY
            metrics.impressions DESC
        LIMIT 200
    """
    
    try:
        creds = get_credentials(target_session_id)
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error analyzing image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image asset performance data found for this customer ID and time period."
        
        # Group results by asset ID
        assets_data = {}
        for result in results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            
            if asset_id not in assets_data:
                assets_data[asset_id] = {
                    'name': asset.get('name', f"Asset {asset_id}"),
                    'url': asset.get('imageAsset', {}).get('fullSize', {}).get('url', 'N/A'),
                    'dimensions': f"{asset.get('imageAsset', {}).get('fullSize', {}).get('widthPixels', 'N/A')} x {asset.get('imageAsset', {}).get('fullSize', {}).get('heightPixels', 'N/A')}",
                    'impressions': 0,
                    'clicks': 0,
                    'conversions': 0,
                    'cost_micros': 0,
                    'campaigns': set(),
                    'ad_groups': set()
                }
            
            # Aggregate metrics
            metrics = result.get('metrics', {})
            assets_data[asset_id]['impressions'] += int(metrics.get('impressions', 0))
            assets_data[asset_id]['clicks'] += int(metrics.get('clicks', 0))
            assets_data[asset_id]['conversions'] += float(metrics.get('conversions', 0))
            assets_data[asset_id]['cost_micros'] += int(metrics.get('costMicros', 0))
            
            # Add campaign and ad group info
            campaign = result.get('campaign', {})
            ad_group = result.get('adGroup', {})
            
            if campaign.get('name'):
                assets_data[asset_id]['campaigns'].add(campaign.get('name'))
            if ad_group.get('name'):
                assets_data[asset_id]['ad_groups'].add(ad_group.get('name'))
        
        # Format the results
        output_lines = [f"Image Asset Performance Analysis for Customer ID {formatted_customer_id} (Last {days} days):"]
        output_lines.append("=" * 100)
        
        # Sort assets by impressions (highest first)
        sorted_assets = sorted(assets_data.items(), key=lambda x: x[1]['impressions'], reverse=True)
        
        for asset_id, data in sorted_assets:
            output_lines.append(f"\nAsset ID: {asset_id}")
            output_lines.append(f"Name: {data['name']}")
            output_lines.append(f"Dimensions: {data['dimensions']}")
            
            # Calculate CTR if there are impressions
            ctr = (data['clicks'] / data['impressions'] * 100) if data['impressions'] > 0 else 0
            
            # Format metrics
            output_lines.append(f"\nPerformance Metrics:")
            output_lines.append(f"  Impressions: {data['impressions']:,}")
            output_lines.append(f"  Clicks: {data['clicks']:,}")
            output_lines.append(f"  CTR: {ctr:.2f}%")
            output_lines.append(f"  Conversions: {data['conversions']:.2f}")
            output_lines.append(f"  Cost (micros): {data['cost_micros']:,}")
            
            # Show where it's used
            output_lines.append(f"\nUsed in {len(data['campaigns'])} campaigns:")
            for campaign in list(data['campaigns'])[:5]:  # Show first 5 campaigns
                output_lines.append(f"  - {campaign}")
            if len(data['campaigns']) > 5:
                output_lines.append(f"  - ... and {len(data['campaigns']) - 5} more")
            
            # Add URL
            if data['url'] != 'N/A':
                output_lines.append(f"\nImage URL: {data['url']}")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except AuthRequiredException as e:
        return str(e)

    except Exception as e:
        return f"Error analyzing image assets: {str(e)}"

@mcp.tool()
async def list_resources(
    ctx: Context,
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    session_id: str = Field(default="default", description="Session ID for multi-user support")
) -> str:
    """
    List valid resources that can be used in GAQL FROM clauses.
    
    Args:
        customer_id: The Google Ads customer ID as a string
        
    Returns:
        Formatted list of valid resources
    """
    # Example query that lists some common resources
    # This might need to be adjusted based on what's available in your API version
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM
            google_ads_field
        WHERE
            google_ads_field.category = 'RESOURCE'
        ORDER BY
            google_ads_field.name
    """
    
    # Use your existing run_gaql function to execute this query
    return await run_gaql(ctx=ctx, customer_id=customer_id, query=query, session_id=session_id)

# --> OAUTH CALLBACK HANDLER
async def google_oauth_callback(request):
    """
    Handle the OAuth 2.0 redirect from Google.
    Exchanges the code for tokens and saves them.
    """
    logger.info("Received OAuth callback request")
    
    # Get query parameters
    params = request.query_params
    code = params.get("code")
    error = params.get("error")
    state = params.get("state", "default") # Default to 'default' if no state provided
    
    if error:
        logger.error(f"OAuth callback error: {error}")
        return Response(f"Authentication Error: {error}", status_code=400)
    
    if not code:
        return Response("Missing 'code' parameter", status_code=400)
        
    # Retrieve the flow from pending_auth_flows
    flow = pending_auth_flows.get(state)
    
    if not flow:
        return Response(f"Error: OAuth flow not found for session '{state}'. Please restart the auth process.", status_code=500)
    
    try:
        # Fetch the token
        logger.info(f"Exchanging code for token (session: {state})...")
        flow.fetch_token(code=code)
        creds = flow.credentials
        
        # Save credentials to session-specific path
        token_path = get_token_path(state)
        logger.info(f"Saving new credentials to {token_path}")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        data = json.loads(creds.to_json())
        
        # Preservation logic
        if os.path.exists(token_path):
            try:
                with open(token_path, "r") as f:
                    old = json.load(f)
                if "refresh_token" in old and "refresh_token" not in data:
                    data["refresh_token"] = old["refresh_token"]
            except Exception:
                pass

        with open(token_path, "w") as f:
            json.dump(data, f, indent=2)
            
        # Clean up the pending flow
        if state in pending_auth_flows:
            del pending_auth_flows[state]
            
        return Response(f"<h1>Authentication Successful!</h1><p>You have successfully logged in as session '<b>{state}</b>'. You can close this window and return to the chat.</p>", media_type="text/html")
        
    except Exception as e:
        logger.error(f"Error in callback: {str(e)}")
        return Response(f"Authentication Failed: {str(e)}", status_code=500)

if __name__ == "__main__":
    import sys
    transport_mode = os.getenv("MCP_SERVER_MODE", "streamable-http")

    try:
        if transport_mode == "std-io":  # std-not-supported fallback
             mcp.run(transport="stdio")
             
        elif transport_mode == "streamable-http" or True: # Force this for now since we need callback
            print(f"Starting Google Ads MCP Server in mode: {transport_mode} with custom callback")
            
            # Get the underlying Starlette app
            # mcp.streamable_http_app is a method that returns the Starlette app
            app = mcp.streamable_http_app()
            
            # Add the callback route
            # Note: FastMCP app is a Starlette app
            app.add_route("/callback", google_oauth_callback, methods=["GET"])
            
            # Run using uvicorn
            uvicorn.run(app, host="0.0.0.0", port=8000)
            
    except (KeyboardInterrupt, SystemExit):
        print("\nStopping Google Ads MCP Server...")
        sys.exit(0)