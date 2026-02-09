"""
Google Analytics 4 MCP Server
Refactored to use centralized Auth Gateway via mcp-auth-client.
"""
from fastmcp import FastMCP, Context
from typing import Any, Dict, List, Optional
import os
import sys
import logging
import httpx
import json
import uvicorn

# Load environment variables FIRST
from dotenv import load_dotenv
load_dotenv()

# Import centralized auth client
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'mcp-auth-client'))
from mcp_auth_client import AuthClient, require_auth
from mcp_auth_client.exceptions import AuthRequiredException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_analytics_server')

# Initialize Auth Client
AUTH_GATEWAY_URL = os.getenv("AUTH_GATEWAY_URL", "http://localhost:8000")
AUTH_GATEWAY_API_KEY = os.getenv("AUTH_GATEWAY_API_KEY", "")

auth_client = AuthClient(
    gateway_url=AUTH_GATEWAY_URL,
    api_key=AUTH_GATEWAY_API_KEY
)

logger.info(f"Auth Gateway URL: {AUTH_GATEWAY_URL}")


async def _get_auth_headers(user_email: str) -> Dict[str, str]:
    """Get authorization headers using centralized auth."""
    try:
        token = await auth_client.get_token("google", user_email)
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    except AuthRequiredException:
        raise
    except Exception as e:
        logger.error(f"Error getting auth headers: {e}")
        raise


mcp = FastMCP("Google Analytics Tools")

# Server startup
logger.info("Starting Google Analytics MCP Server (Centralized Auth)...")


@mcp.tool
async def list_properties(
    user_email: str,
    account_id: str = "",
    ctx: Context = None
) -> Dict[str, Any]:
    """List all Google Analytics 4 accounts with their associated properties.
    
    Args:
        user_email: User's email address for authentication
        account_id: Optional specific Google Analytics account ID to list properties for.
                   If not provided, will list all accessible accounts with their properties.
    
    Returns:
        Hierarchical structure showing Account ID/Name with all associated Property IDs/Names
    """
    if ctx:
        if account_id:
            await ctx.info(f"Listing properties for account {account_id}...")
        else:
            await ctx.info("Listing all accessible Google Analytics accounts and properties...")

    try:
        headers = await _get_auth_headers(user_email)
        
        accounts_with_properties = []
        async with httpx.AsyncClient() as client:

            if account_id:
                # Get specific account info
                account_url = f"https://analyticsadmin.googleapis.com/v1/accounts/{account_id}"
                account_response = await client.get(account_url, headers=headers)
                api_version = 'v1'

                if account_response.status_code != 200:
                    account_url = f"https://analyticsadmin.googleapis.com/v1beta/accounts/{account_id}"
                    account_response = await client.get(account_url, headers=headers)
                    api_version = 'v1beta'

                if account_response.status_code != 200:
                    raise Exception(f"Admin API error: {account_response.status_code} - {account_response.text}")

                account = account_response.json()
                account_name = account.get('name', '')

                # Get properties for this account
                properties = []
                properties_next_token = None
                
                while True:
                    properties_url = f"https://analyticsadmin.googleapis.com/{api_version}/{account_name}/properties"
                    params = {'pageToken': properties_next_token} if properties_next_token else {}
                    properties_response = await client.get(properties_url, headers=headers, params=params)

                    if properties_response.status_code == 200:
                        properties_results = properties_response.json()
                        properties.extend(properties_results.get('properties', []))
                        properties_next_token = properties_results.get('nextPageToken')
                    else:
                        break
                    
                    if not properties_next_token:
                        break

                accounts_with_properties.append({
                    'accountId': account_id,
                    'accountName': account.get('displayName', 'Unnamed Account'),
                    'propertyCount': len(properties),
                    'properties': [
                        {
                            'propertyId': prop.get('name', '').replace('properties/', ''),
                            'displayName': prop.get('displayName', 'Unnamed Property'),
                            'timeZone': prop.get('timeZone', 'Unknown'),
                            'currencyCode': prop.get('currencyCode', 'Unknown'),
                            'createTime': prop.get('createTime', 'Unknown')
                        }
                        for prop in properties
                    ]
                })
            else:
                # List all accessible accounts
                accounts_url = "https://analyticsadmin.googleapis.com/v1/accountSummaries"
                api_version = 'v1'
                
                accounts_response = await client.get(accounts_url, headers=headers)
                
                if accounts_response.status_code != 200:
                    accounts_url = "https://analyticsadmin.googleapis.com/v1beta/accountSummaries"
                    accounts_response = await client.get(accounts_url, headers=headers)
                    api_version = 'v1beta'

                if accounts_response.status_code != 200:
                    raise Exception(f"Admin API error: {accounts_response.status_code} - {accounts_response.text}")
                
                account_summaries = accounts_response.json().get('accountSummaries', [])
                
                for account_summary in account_summaries:
                    account_id_val = account_summary.get('account', '').replace('accounts/', '')
                    property_summaries = account_summary.get('propertySummaries', [])
                    
                    accounts_with_properties.append({
                        'accountId': account_id_val,
                        'accountName': account_summary.get('displayName', 'Unnamed Account'),
                        'propertyCount': len(property_summaries),
                        'properties': [
                            {
                                'propertyId': prop.get('property', '').replace('properties/', ''),
                                'displayName': prop.get('displayName', 'Unnamed Property')
                            }
                            for prop in property_summaries
                        ]
                    })

        return {
            'success': True,
            'totalAccounts': len(accounts_with_properties),
            'accounts': accounts_with_properties
        }

    except AuthRequiredException as e:
        return {
            'success': False,
            'error': 'authentication_required',
            'message': str(e),
            'auth_url': e.auth_url
        }
    except Exception as e:
        logger.error(f"Error listing properties: {e}")
        return {'success': False, 'error': str(e)}


@mcp.tool
async def get_page_views(
    user_email: str,
    property_id: str,
    start_date: str,
    end_date: str,
    dimensions: Optional[List[str]] = None,
    ctx: Context = None
) -> Dict[str, Any]:
    """Get page view metrics for a specific date range from Google Analytics 4.
    
    Args:
        user_email: User's email address for authentication
        property_id: Google Analytics 4 property ID (numeric, e.g., "123456789")
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        dimensions: List of dimensions to group by (optional, defaults to ["pagePath"])
    
    Returns:
        Page view metrics grouped by specified dimensions
    """
    if ctx:
        await ctx.info(f"Getting page views for property {property_id} from {start_date} to {end_date}...")

    try:
        headers = await _get_auth_headers(user_email)
        
        url = f"https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport"

        payload = {
            'dateRanges': [{'startDate': start_date, 'endDate': end_date}],
            'metrics': [{'name': 'screenPageViews'}]
        }

        if dimensions and len(dimensions) > 0:
            payload['dimensions'] = [{'name': dim} for dim in dimensions]
        else:
            payload['dimensions'] = [{'name': 'pagePath'}]

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Google Analytics API error: {response.status_code} - {response.text}")

        results = response.json()

        if not results.get('rows'):
            return {
                'success': True,
                'propertyId': property_id,
                'dateRange': {'startDate': start_date, 'endDate': end_date},
                'message': 'No data found',
                'data': []
            }

        dimension_headers = [h.get('name', '') for h in results.get('dimensionHeaders', [])]
        metric_headers = [h.get('name', '') for h in results.get('metricHeaders', [])]

        data = []
        for row in results.get('rows', []):
            row_data = {}
            for i, dim_value in enumerate(row.get('dimensionValues', [])):
                if i < len(dimension_headers):
                    row_data[dimension_headers[i]] = dim_value.get('value', '')
            for i, metric_value in enumerate(row.get('metricValues', [])):
                if i < len(metric_headers):
                    row_data[metric_headers[i]] = metric_value.get('value', '')
            data.append(row_data)

        return {
            'success': True,
            'propertyId': property_id,
            'dateRange': {'startDate': start_date, 'endDate': end_date},
            'rowCount': len(data),
            'data': data
        }

    except AuthRequiredException as e:
        return {
            'success': False,
            'error': 'authentication_required',
            'message': str(e),
            'auth_url': e.auth_url
        }
    except Exception as e:
        logger.error(f"Error getting page views: {e}")
        return {'success': False, 'error': str(e)}


@mcp.tool
async def get_active_users(
    user_email: str,
    property_id: str,
    start_date: str,
    end_date: str,
    dimensions: Optional[List[str]] = None,
    ctx: Context = None
) -> Dict[str, Any]:
    """Get active user metrics from Google Analytics 4.
    
    Args:
        user_email: User's email address for authentication
        property_id: Google Analytics 4 property ID
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        dimensions: List of dimensions to group by (optional, defaults to ["date"])
    """
    if ctx:
        await ctx.info(f"Getting active users for property {property_id}...")

    try:
        headers = await _get_auth_headers(user_email)
        
        url = f"https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport"

        payload = {
            'dateRanges': [{'startDate': start_date, 'endDate': end_date}],
            'metrics': [{'name': 'activeUsers'}, {'name': 'newUsers'}]
        }

        if dimensions and len(dimensions) > 0:
            payload['dimensions'] = [{'name': dim} for dim in dimensions]
        else:
            payload['dimensions'] = [{'name': 'date'}]

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Google Analytics API error: {response.status_code} - {response.text}")

        results = response.json()
        dimension_headers = [h.get('name', '') for h in results.get('dimensionHeaders', [])]
        metric_headers = [h.get('name', '') for h in results.get('metricHeaders', [])]

        data = []
        for row in results.get('rows', []):
            row_data = {}
            for i, dim_value in enumerate(row.get('dimensionValues', [])):
                if i < len(dimension_headers):
                    row_data[dimension_headers[i]] = dim_value.get('value', '')
            for i, metric_value in enumerate(row.get('metricValues', [])):
                if i < len(metric_headers):
                    row_data[metric_headers[i]] = metric_value.get('value', '')
            data.append(row_data)

        return {
            'success': True,
            'propertyId': property_id,
            'dateRange': {'startDate': start_date, 'endDate': end_date},
            'rowCount': len(data),
            'data': data
        }

    except AuthRequiredException as e:
        return {
            'success': False,
            'error': 'authentication_required',
            'auth_url': e.auth_url
        }
    except Exception as e:
        logger.error(f"Error getting active users: {e}")
        return {'success': False, 'error': str(e)}


@mcp.tool
async def get_traffic_sources(
    user_email: str,
    property_id: str,
    start_date: str,
    end_date: str,
    ctx: Context = None
) -> Dict[str, Any]:
    """Get traffic source metrics from Google Analytics 4.
    
    Args:
        user_email: User's email address for authentication
        property_id: Google Analytics 4 property ID
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
    """
    if ctx:
        await ctx.info(f"Getting traffic sources for property {property_id}...")

    try:
        headers = await _get_auth_headers(user_email)
        
        url = f"https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport"

        payload = {
            'dateRanges': [{'startDate': start_date, 'endDate': end_date}],
            'dimensions': [{'name': 'sessionSource'}, {'name': 'sessionMedium'}],
            'metrics': [{'name': 'sessions'}, {'name': 'totalUsers'}, {'name': 'screenPageViews'}]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Google Analytics API error: {response.status_code} - {response.text}")

        results = response.json()
        dimension_headers = [h.get('name', '') for h in results.get('dimensionHeaders', [])]
        metric_headers = [h.get('name', '') for h in results.get('metricHeaders', [])]

        data = []
        for row in results.get('rows', []):
            row_data = {}
            for i, dim_value in enumerate(row.get('dimensionValues', [])):
                if i < len(dimension_headers):
                    row_data[dimension_headers[i]] = dim_value.get('value', '')
            for i, metric_value in enumerate(row.get('metricValues', [])):
                if i < len(metric_headers):
                    row_data[metric_headers[i]] = metric_value.get('value', '')
            data.append(row_data)

        return {
            'success': True,
            'propertyId': property_id,
            'dateRange': {'startDate': start_date, 'endDate': end_date},
            'rowCount': len(data),
            'data': data
        }

    except AuthRequiredException as e:
        return {
            'success': False,
            'error': 'authentication_required',
            'auth_url': e.auth_url
        }
    except Exception as e:
        logger.error(f"Error getting traffic sources: {e}")
        return {'success': False, 'error': str(e)}


@mcp.tool
async def run_report(
    user_email: str,
    property_id: str,
    start_date: str,
    end_date: str,
    metrics: List[str],
    dimensions: Optional[List[str]] = None,
    limit: int = 10000,
    ctx: Context = None
) -> Dict[str, Any]:
    """Run a custom Google Analytics 4 report with specified metrics and dimensions.
    
    Args:
        user_email: User's email address for authentication
        property_id: Google Analytics 4 property ID
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        metrics: List of metrics to include (e.g., ["sessions", "totalUsers"])
        dimensions: List of dimensions to group by (optional)
        limit: Maximum number of rows to return (default: 10000)
    """
    if ctx:
        await ctx.info(f"Running custom report for property {property_id}...")

    try:
        headers = await _get_auth_headers(user_email)
        
        url = f"https://analyticsdata.googleapis.com/v1beta/properties/{property_id}:runReport"

        payload = {
            'dateRanges': [{'startDate': start_date, 'endDate': end_date}],
            'metrics': [{'name': m} for m in metrics],
            'limit': limit
        }

        if dimensions:
            payload['dimensions'] = [{'name': d} for d in dimensions]

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            raise Exception(f"Google Analytics API error: {response.status_code} - {response.text}")

        results = response.json()
        dimension_headers = [h.get('name', '') for h in results.get('dimensionHeaders', [])]
        metric_headers = [h.get('name', '') for h in results.get('metricHeaders', [])]

        data = []
        for row in results.get('rows', []):
            row_data = {}
            for i, dim_value in enumerate(row.get('dimensionValues', [])):
                if i < len(dimension_headers):
                    row_data[dimension_headers[i]] = dim_value.get('value', '')
            for i, metric_value in enumerate(row.get('metricValues', [])):
                if i < len(metric_headers):
                    row_data[metric_headers[i]] = metric_value.get('value', '')
            data.append(row_data)

        return {
            'success': True,
            'propertyId': property_id,
            'dateRange': {'startDate': start_date, 'endDate': end_date},
            'metrics': metrics,
            'dimensions': dimensions or [],
            'rowCount': len(data),
            'data': data
        }

    except AuthRequiredException as e:
        return {
            'success': False,
            'error': 'authentication_required',
            'auth_url': e.auth_url
        }
    except Exception as e:
        logger.error(f"Error running report: {e}")
        return {'success': False, 'error': str(e)}


if __name__ == "__main__":
    if "--http" in sys.argv:
        port = int(os.getenv("PORT", "8002"))
        logger.info(f"Starting with HTTP transport on http://0.0.0.0:{port}")
        logger.info(f"MCP endpoint: http://0.0.0.0:{port}/mcp")
        logger.info(f"Using Auth Gateway at: {AUTH_GATEWAY_URL}")
        
        app = mcp.http_app()
        
        try:
            uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
            sys.exit(0)
    else:
        logger.info("Starting with STDIO transport for Claude Desktop")
        mcp.run(transport="stdio")
