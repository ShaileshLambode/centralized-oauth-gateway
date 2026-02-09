# Centralized OAuth Gateway for MCP Servers

Centralized OAuth authentication system for Google Ads and Google Analytics MCP servers.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  Google Ads MCP │────▶│   Auth Gateway  │────▶ PostgreSQL
├─────────────────┤     │    (FastAPI)    │
│  Analytics MCP  │────▶│                 │────▶ Google OAuth
└─────────────────┘     └─────────────────┘
        via mcp-auth-client
```

## Components

| Directory | Description |
|-----------|-------------|
| `auth-gateway/` | FastAPI OAuth gateway with PostgreSQL |
| `mcp-auth-client/` | Python package for MCP servers |
| `google-ads-mcp-oauth-main/` | Google Ads MCP server |
| `google-analytics-4-mcp-oauth/` | Google Analytics MCP server |

## Quick Start (Development)

```bash
# 1. Generate keys
cd auth-gateway
python scripts/generate_keys.py --all

# 2. Configure environment
cp .env.example .env
# Edit .env with your Google OAuth credentials

# 3. Start services
docker-compose up -d

# 4. Initialize database
docker exec auth-gateway python scripts/init_db.py
```

## Production Deployment

```bash
# 1. Configure production environment
cp .env.prod.example .env
# Edit .env with production values

# 2. Start production stack
docker-compose -f docker-compose.prod.yml up -d
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/init` | Start OAuth flow |
| GET | `/auth/callback/{provider}` | OAuth callback |
| POST | `/auth/token` | Get/refresh token |
| GET | `/auth/status/{session_id}` | Check auth status |
| DELETE | `/auth/revoke` | Revoke credentials |

## MCP Server Usage

```python
from mcp_auth_client import AuthClient

client = AuthClient(
    gateway_url="http://localhost:8000",
    api_key="your-api-key"
)

# Get token (auto-refreshes if expired)
token = await client.get_token("google", "user@example.com")
```

## Security Features

- Fernet encryption (AES-128-CBC + HMAC-SHA256)
- API key authentication
- Key rotation support
- CSRF protection via state parameter
- HTTPS via Traefik (production)

## License

MIT
