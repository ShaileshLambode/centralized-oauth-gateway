# Centralized OAuth Gateway - Complete Setup Guide

A production-ready centralized OAuth authentication system for Google Ads and Google Analytics MCP servers.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (Development)](#quick-start-development)
3. [Production Deployment](#production-deployment)
4. [Configuration Reference](#configuration-reference)
5. [API Endpoints](#api-endpoints)
6. [MCP Server Integration](#mcp-server-integration)
7. [Key Rotation](#key-rotation)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Python 3.11+**
- **Docker & Docker Compose**
- **PostgreSQL 15+** (or use Docker)
- **Google Cloud Project** with OAuth 2.0 credentials

### Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable APIs:
   - Google Analytics Admin API
   - Google Analytics Data API
   - Google Ads API
4. Create OAuth 2.0 credentials:
   - Application type: **Web application**
   - Authorized redirect URI: `http://localhost:8000/auth/callback/google` (dev) or `https://auth.yourdomain.com/auth/callback/google` (prod)
5. Note your **Client ID** and **Client Secret**

---

## Quick Start (Development)

### Step 1: Clone the Repository

```bash
git clone https://github.com/ShaileshLambode/centralized-oauth-gateway.git
cd centralized-oauth-gateway
```

### Step 2: Generate Security Keys

```bash
cd auth-gateway
python scripts/generate_keys.py --all
```

This outputs:
```
AUTH_GATEWAY_ENCRYPTION_KEY=<your-key>
AUTH_GATEWAY_ENCRYPTION_KEY_SALT=<your-salt>
AUTH_GATEWAY_API_KEY=<your-api-key>
```

### Step 3: Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit with your values
nano .env
```

**.env file contents:**
```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/auth_gateway

# Security Keys (from Step 2)
AUTH_GATEWAY_ENCRYPTION_KEY=<paste-from-step-2>
AUTH_GATEWAY_ENCRYPTION_KEY_SALT=<paste-from-step-2>
AUTH_GATEWAY_API_KEY=<paste-from-step-2>

# Google OAuth
GOOGLE_CLIENT_ID=<your-client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/callback/google

# Server
ENVIRONMENT=development
LOG_LEVEL=INFO
```

### Step 4: Start with Docker Compose

```bash
# Go back to project root
cd ..

# Start PostgreSQL + Auth Gateway
docker-compose up -d
```

### Step 5: Verify Installation

```bash
# Check health
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","database":"connected","encryption":"operational","version":"1.0.0","timestamp":"..."}
```

### Step 6: Run MCP Servers

**Google Analytics MCP:**
```bash
cd google-analytics-4-mcp-oauth-google-analytics-4-mcp-oauth/google-analytics-4-mcp-oauth-google-analytics-4-mcp-oauth

# Configure
cp .env.example .env
# Edit .env:
# AUTH_GATEWAY_URL=http://localhost:8000
# AUTH_GATEWAY_API_KEY=<same-key-from-step-2>

# Install dependencies
pip install -r requirements.txt

# Run
python server_centralized.py --http
```

**Google Ads MCP:**
```bash
cd google-ads-mcp-oauth-main/google-ads-mcp-oauth-main

# Configure
cp .env.example .env
# Edit .env:
# AUTH_GATEWAY_URL=http://localhost:8000
# AUTH_GATEWAY_API_KEY=<same-key-from-step-2>
# GOOGLE_ADS_DEVELOPER_TOKEN=<your-dev-token>

# Install dependencies
pip install -r requirements.txt

# Run
python google_ads_server_centralized.py
```

---

## Production Deployment

### Step 1: Configure Production Environment

```bash
cp .env.prod.example .env
```

Edit `.env` with production values:
```env
# Database
DB_USER=postgres
DB_PASSWORD=<strong-password>

# Security
AUTH_GATEWAY_ENCRYPTION_KEY=<generated-key>
AUTH_GATEWAY_ENCRYPTION_KEY_SALT=<generated-salt>
AUTH_GATEWAY_API_KEY=<generated-api-key>

# Google OAuth
GOOGLE_CLIENT_ID=<your-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_REDIRECT_URI=https://auth.yourdomain.com/auth/callback/google

# Domain (for Traefik SSL)
AUTH_DOMAIN=auth.yourdomain.com
ACME_EMAIL=admin@yourdomain.com

# Logging
LOG_LEVEL=WARNING
```

### Step 2: Deploy with Production Stack

```bash
docker-compose -f docker-compose.prod.yml up -d
```

This starts:
- **PostgreSQL** - Database (internal network only)
- **Auth Gateway** - OAuth service
- **GA MCP Server** - Port 8001
- **GAds MCP Server** - Port 8002
- **Traefik** - SSL/HTTPS on ports 80/443

### Step 3: Verify SSL

```bash
curl https://auth.yourdomain.com/health
```

---

## Configuration Reference

### Auth Gateway Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `AUTH_GATEWAY_ENCRYPTION_KEY` | Yes | - | 32+ char encryption key |
| `AUTH_GATEWAY_ENCRYPTION_KEY_SALT` | No | - | Optional salt for key derivation |
| `AUTH_GATEWAY_API_KEY` | Yes | - | API key for MCP servers |
| `AUTH_GATEWAY_ROTATION_KEYS` | No | - | Comma-separated old keys |
| `GOOGLE_CLIENT_ID` | Yes | - | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | - | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | No | localhost | OAuth callback URL |
| `ENVIRONMENT` | No | development | `development` or `production` |
| `LOG_LEVEL` | No | INFO | DEBUG, INFO, WARNING, ERROR |
| `LOG_FORMAT` | No | json | `json` or `text` |
| `SESSION_EXPIRY_MINUTES` | No | 15 | OAuth session timeout |
| `TOKEN_REFRESH_BUFFER_SECONDS` | No | 300 | Refresh tokens this early |

### MCP Server Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH_GATEWAY_URL` | Yes | URL of Auth Gateway |
| `AUTH_GATEWAY_API_KEY` | Yes | Same API key as gateway |
| `GOOGLE_ADS_DEVELOPER_TOKEN` | Yes* | For Google Ads MCP only |
| `GOOGLE_ADS_LOGIN_CUSTOMER_ID` | No | MCC manager account ID |

---

## API Endpoints

### Auth Gateway Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/init` | API Key | Start OAuth flow |
| GET | `/auth/callback/{provider}` | None | OAuth callback (user-facing) |
| GET | `/auth/status/{session_id}` | None | Check OAuth status |
| POST | `/auth/token` | API Key | Get/refresh access token |
| GET | `/auth/providers/{email}` | API Key | List user's providers |
| DELETE | `/auth/revoke` | API Key | Revoke credentials |
| GET | `/health` | None | Health check |

### Example: Get Token

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"provider": "google", "user_email": "user@example.com"}'
```

### Example: Init OAuth

```bash
curl -X POST http://localhost:8000/auth/init \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"provider": "google", "user_email": "user@example.com"}'
```

---

## MCP Server Integration

### Using mcp-auth-client

```python
from mcp_auth_client import AuthClient
from mcp_auth_client.exceptions import AuthRequiredException

# Initialize client
auth_client = AuthClient(
    gateway_url="http://localhost:8000",
    api_key="your-api-key"
)

# Get token (auto-refreshes if expired)
try:
    token = await auth_client.get_token("google", "user@example.com")
    # Use token with Google APIs
except AuthRequiredException as e:
    # User needs to authenticate
    print(f"Please visit: {e.auth_url}")
```

### In MCP Tool Functions

```python
@mcp.tool
async def my_tool(user_email: str):
    """Tool that requires Google authentication."""
    try:
        headers = {
            "Authorization": f"Bearer {await auth_client.get_token('google', user_email)}",
            "Content-Type": "application/json"
        }
        # Make API call...
    except AuthRequiredException as e:
        return {
            "error": "authentication_required",
            "auth_url": e.auth_url
        }
```

---

## Key Rotation

### Rotate Encryption Key (Zero Downtime)

```bash
# 1. Generate new key
cd auth-gateway
python scripts/generate_keys.py --rotate

# 2. Update .env
# Move current key to AUTH_GATEWAY_ROTATION_KEYS
# Set new key as AUTH_GATEWAY_ENCRYPTION_KEY

# 3. Restart gateway
docker-compose restart auth-gateway

# 4. Re-encrypt existing tokens
docker exec auth-gateway python scripts/reencrypt_tokens.py

# 5. After 48 hours, remove AUTH_GATEWAY_ROTATION_KEYS
```

---

## Troubleshooting

### Database Connection Failed

```bash
# Check if PostgreSQL is running
docker-compose ps

# Check logs
docker-compose logs db
```

### Invalid API Key

Ensure `AUTH_GATEWAY_API_KEY` is exactly the same in:
- Auth Gateway `.env`
- MCP Server `.env`

### OAuth Redirect Mismatch

1. Check `GOOGLE_REDIRECT_URI` matches Google Cloud Console
2. Ensure no trailing slash
3. Protocol must match (http vs https)

### Token Decryption Failed

If you changed encryption keys without rotation:
```bash
# Users will need to re-authenticate
# Old tokens cannot be decrypted
```

### Health Check Shows "degraded"

```bash
# Check database
curl http://localhost:8000/health

# If database = "disconnected":
docker-compose restart db
docker-compose restart auth-gateway
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Your Application                          │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
        ┌───────────────────┐     ┌───────────────────┐
        │   Google Ads MCP   │     │ Google Analytics  │
        │      Server        │     │    MCP Server     │
        └─────────┬──────────┘     └─────────┬─────────┘
                  │    mcp-auth-client       │
                  └────────────┬─────────────┘
                               ▼
                    ┌───────────────────┐
                    │   Auth Gateway    │
                    │    (FastAPI)      │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
     ┌──────────────┐  ┌────────────┐  ┌────────────┐
     │  PostgreSQL  │  │  Fernet    │  │  Google    │
     │   Database   │  │ Encryption │  │   OAuth    │
     └──────────────┘  └────────────┘  └────────────┘
```

---

## License

MIT License
