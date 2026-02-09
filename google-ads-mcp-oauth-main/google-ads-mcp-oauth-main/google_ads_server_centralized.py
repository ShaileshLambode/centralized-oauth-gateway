"""
Google Ads MCP Server (Centralized Auth)
Refactored to use Auth Gateway via mcp-auth-client.
"""
from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
import logging

# MCP
from mcp.server.fastmcp import FastMCP, Context
import uvicorn
import sys

# Load environment variables FIRST
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

# Import centralized auth client
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'mcp-auth-client'))
from mcp_auth_client import AuthClient
from mcp_auth_client.exceptions import AuthRequiredException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

# Relax token scope to allow extra scopes
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# Initialize Auth Client
AUTH_GATEWAY_URL = os.getenv("AUTH_GATEWAY_URL", "http://localhost:8000")
AUTH_GATEWAY_API_KEY = os.getenv("AUTH_GATEWAY_API_KEY", "")

auth_client = AuthClient(
    gateway_url=AUTH_GATEWAY_URL,
    api_key=AUTH_GATEWAY_API_KEY
)

logger.info(f"Auth Gateway URL: {AUTH_GATEWAY_URL}")

# Environment configuration
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
API_VERSION = "v19"

mcp = FastMCP("google_ads_mcp", host="0.0.0.0")

logger.info("Starting Google Ads MCP Server (Centralized Auth)...")


def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)


async def get_auth_headers(user_email: str) -> Dict[str, str]:
    """Get authorization headers using centralized auth."""
    try:
        token = await auth_client.get_token("google", user_email)
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN
        }
        if GOOGLE_ADS_LOGIN_CUSTOMER_ID:
            headers['login-customer-id'] = format_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
        return headers
    except AuthRequiredException:
        raise
    except Exception as e:
        logger.error(f"Error getting auth headers: {e}")
        raise


@mcp.tool()
async def list_accounts(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication")
) -> str:
    """
    Lists all client (non-manager) Google Ads accounts under all accessible managers.
    
    Args:
        user_email: User's email address for authentication
        
    Returns:
        Formatted list of all client accounts
    """
    try:
        headers = await get_auth_headers(user_email)

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
                if not cc["manager"]:
                    results.append(
                        f"  - Customer ID: {format_customer_id(cc['id'])} | "
                        f"Name: {cc.get('descriptiveName', 'N/A')}"
                    )

        return "\n".join(results)

    except AuthRequiredException as e:
        return f"🔐 AUTHENTICATION REQUIRED\n\nPlease visit: {e.auth_url}\n\nSay 'done' after completing."

    except Exception as e:
        return f"Error listing client accounts: {str(e)}"


@mcp.tool()
async def execute_gaql_query(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication"),
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    query: str = Field(description="Valid GAQL query string")
) -> str:
    """
    Execute a custom GAQL (Google Ads Query Language) query.
    
    Args:
        user_email: User's email address for authentication
        customer_id: The Google Ads customer ID
        query: The GAQL query to execute
        
    Returns:
        Formatted query results or error message
    """
    try:
        headers = await get_auth_headers(user_email)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
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
        
        result_lines.append(" | ".join(fields))
        result_lines.append("-" * 80)
        
        for row in results['results']:
            values = []
            for key in row:
                if isinstance(row[key], dict):
                    for subkey in row[key]:
                        value = row[key][subkey]
                        if key == 'metrics' and subkey == 'costMicros':
                            value = f"${int(value)/1000000:.2f}"
                        values.append(str(value))
                else:
                    values.append(str(row[key]))
            result_lines.append(" | ".join(values))
        
        result_lines.append("-" * 80)
        result_lines.append(f"Total rows: {len(results['results'])}")
        
        return "\n".join(result_lines)

    except AuthRequiredException as e:
        return f"🔐 AUTHENTICATION REQUIRED\n\nPlease visit: {e.auth_url}\n\nSay 'done' after completing."

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"


@mcp.tool()
async def resolve_customer(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication"),
    customer: str = Field(description="Customer name or customer ID")
) -> str:
    """
    Resolve a customer name or ID into a valid Google Ads customer ID.
    
    Args:
        user_email: User's email address for authentication
        customer: Customer name or ID to resolve
    """
    # Case 1: already looks like an ID
    digits = ''.join(c for c in customer if c.isdigit())
    if len(digits) == 10:
        return format_customer_id(digits)

    # Case 2: treat as name
    accounts = await list_accounts(ctx=ctx, user_email=user_email)
    
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

    if len(matches) == 0:
        return f"No accounts found matching '{customer}'."

    if len(matches) == 1:
        return matches[0][0]

    result_lines = ["Multiple matches found:"]
    for cid, name in matches:
        result_lines.append(f"  - {cid}: {name}")
    return "\n".join(result_lines)


@mcp.tool()
async def get_campaign_performance(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication"),
    customer_id: str = Field(description="Google Ads customer ID"),
    date_range: str = Field(default="LAST_30_DAYS", description="Date range (e.g., LAST_7_DAYS, LAST_30_DAYS)")
) -> str:
    """
    Get campaign performance metrics.
    
    Args:
        user_email: User's email address for authentication
        customer_id: Google Ads customer ID
        date_range: Date range for the report
    """
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
    return await execute_gaql_query(ctx=ctx, user_email=user_email, customer_id=customer_id, query=query)


@mcp.tool()
async def get_ad_performance(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication"),
    customer_id: str = Field(description="Google Ads customer ID"),
    date_range: str = Field(default="LAST_30_DAYS", description="Date range")
) -> str:
    """
    Get ad performance metrics.
    """
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
    return await execute_gaql_query(ctx=ctx, user_email=user_email, customer_id=customer_id, query=query)


@mcp.tool()
async def analytics_router(
    ctx: Context,
    user_email: str = Field(description="User's email address for authentication"),
    customer_id: str = Field(description="Google Ads customer ID"),
    intent: str = Field(description="What to fetch: campaigns, ads, creatives, images, asset_usage"),
    date_range: str = Field(default="LAST_30_DAYS", description="Date range")
) -> str:
    """
    Route to the appropriate analytics query based on intent.
    """
    intent = intent.lower().strip()

    if intent in ("campaigns", "campaign", "campaign performance"):
        return await get_campaign_performance(ctx=ctx, user_email=user_email, customer_id=customer_id, date_range=date_range)

    if intent in ("ad", "ads", "ad performance"):
        return await get_ad_performance(ctx=ctx, user_email=user_email, customer_id=customer_id, date_range=date_range)

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
        return await execute_gaql_query(ctx=ctx, user_email=user_email, customer_id=customer_id, query=query)

    if intent in ("image", "images", "image asset", "image assets", "assets"):
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
        return await execute_gaql_query(ctx=ctx, user_email=user_email, customer_id=customer_id, query=query)

    return "❌ Unknown intent. Valid: campaigns, ads, creatives, images, asset_usage"


if __name__ == "__main__":
    transport_mode = os.getenv("MCP_SERVER_MODE", "streamable-http")

    try:
        if transport_mode == "stdio":
            logger.info("Starting with STDIO transport")
            mcp.run(transport="stdio")
        else:
            port = int(os.getenv("PORT", "8001"))
            logger.info(f"Starting with HTTP transport on http://0.0.0.0:{port}")
            logger.info(f"Using Auth Gateway at: {AUTH_GATEWAY_URL}")
            
            app = mcp.streamable_http_app()
            uvicorn.run(app, host="0.0.0.0", port=port)
            
    except (KeyboardInterrupt, SystemExit):
        logger.info("\nStopping Google Ads MCP Server...")
        sys.exit(0)
