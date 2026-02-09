# mcp-auth-client

Shared OAuth authentication client for MCP servers. Communicates with the centralized Auth Gateway.

## Installation

```bash
# From local source
pip install -e ./mcp-auth-client

# Or from repository (when published)
pip install git+https://github.com/your-org/mcp-auth-client.git
```

## Quick Start

```python
from mcp_auth_client import AuthClient, require_auth
from mcp_auth_client.exceptions import AuthRequiredException
import os

# Initialize client
auth_client = AuthClient(
    gateway_url=os.getenv("AUTH_GATEWAY_URL", "http://localhost:8000"),
    api_key=os.getenv("AUTH_GATEWAY_API_KEY")
)

# Option 1: Using decorator (recommended)
@server.tool()
@require_auth(auth_client, provider="google")
async def my_tool(user_email: str, query: str):
    """Tool that requires Google authentication."""
    # If we get here, user is authenticated
    token = await auth_client.get_token("google", user_email)
    headers = {"Authorization": f"Bearer {token}"}
    # ... make API call ...

# Option 2: Manual token retrieval
async def my_function(user_email: str):
    try:
        token = await auth_client.get_token("google", user_email)
        # Use token
    except AuthRequiredException as e:
        print(f"Please authenticate: {e.auth_url}")
        raise
```

## API Reference

### AuthClient

```python
AuthClient(gateway_url: str, api_key: str, timeout: float = 30.0)
```

**Methods:**

- `get_token(provider, user_email)` → `str`: Get valid access token (auto-refreshes)
- `is_authenticated(provider, user_email)` → `bool`: Check auth status
- `init_oauth(provider, user_email, scopes?)` → `AuthSessionInfo`: Start OAuth flow
- `get_auth_status(session_id)` → `dict`: Check OAuth session status
- `list_providers(user_email)` → `list`: List user's authorized providers
- `revoke(provider, user_email)` → `bool`: Delete credentials

### @require_auth Decorator

```python
@require_auth(auth_client, provider="google", email_param="user_email")
```

Ensures authentication before function execution. Raises `AuthRequiredException` if not authenticated.

## Environment Variables

```bash
AUTH_GATEWAY_URL=http://localhost:8000
AUTH_GATEWAY_API_KEY=your-api-key
```
