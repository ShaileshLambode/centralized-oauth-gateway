# Centralized OAuth Authentication for Multiple MCP Servers
## Complete Implementation Plan v2.0

> **Last Updated**: February 9, 2026  
> **Status**: Ready for Implementation  
> **Estimated Timeline**: 3-4 weeks

---

## 📋 Executive Summary

Implement a **centralized Auth Gateway** (FastAPI + PostgreSQL) that manages OAuth tokens for all MCP servers, replacing per-server token handling with a shared, secure authentication layer.

### Key Features
- ✅ **Centralized Token Management**: One gateway for all MCP servers
- ✅ **Email-based User Identification**: Uses email addresses as unique identifiers
- ✅ **Enterprise-grade Encryption**: Fernet (AES-128) with key rotation
- ✅ **PostgreSQL Database**: Scalable, production-ready storage
- ✅ **Zero-downtime Key Rotation**: Background re-encryption support
- ✅ **Docker-based Deployment**: Easy containerized setup

---

## 🎯 Decisions Confirmed

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Database** | PostgreSQL | Scalable, concurrent access, production-ready |
| **Profile ID** | Email Address | Naturally unique, user-friendly, audit-friendly |
| **Encryption** | Fernet + Key Rotation | Industry standard, NIST approved, rotation support |
| **Key Storage** | Environment Variables | Simple for MVP, document Vault for future |
| **Migration Strategy** | Clean Start (Re-auth) | Simpler than token migration, less error-prone |
| **Callback Domain** | Subdomain (auth.domain.com) | Clean separation, scalable |

---

## 📊 Current State Analysis

### Google Ads MCP Server (`google_ads_server.py`)
**Current OAuth Implementation:**
- Lines 209-349: Standalone `get_oauth_credentials()` function
- Token Storage: File-based at `tokens/{session_id}.json`
- Session Management: Global `pending_auth_flows` dict
- Auth Exception: Custom `AuthRequiredException` class

### Google Analytics MCP Server (`oauth/google_auth.py`)
**Current OAuth Implementation:**
- Lines 129-273: `get_oauth_credentials()` function
- Token Storage: File-based at `GOOGLE_GA4_TOKEN_PATH/{session_id}.json`
- Session Management: Global variables pattern
- Callback Handler: `google_oauth_callback()` async function

### Common OAuth Pattern (To Centralize)
```
1. Check token exists → Load credentials
2. Token expired? → Refresh using refresh_token
3. No token? → Generate auth URL → Wait for callback
4. After callback → Exchange code for tokens → Save tokens
```

**Problem**: Each MCP server duplicates this logic with slight variations.

**Solution**: Extract to centralized Auth Gateway.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Hetzner Infrastructure                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │         Auth Gateway (FastAPI)                      │     │
│  │  ┌──────────────────────────────────────────┐      │     │
│  │  │  /auth/init    - Start OAuth flow        │      │     │
│  │  │  /auth/callback - Handle provider redirect│     │     │
│  │  │  /auth/status  - Check auth completion   │      │     │
│  │  │  /auth/token   - Get/refresh tokens      │      │     │
│  │  └──────────────────────────────────────────┘      │     │
│  │                      ▼                              │     │
│  │  ┌──────────────────────────────────────────┐      │     │
│  │  │  Encryption Layer (Fernet)               │      │     │
│  │  │  - AES-128-CBC + HMAC                    │      │     │
│  │  │  - Key rotation support                  │      │     │
│  │  └──────────────────────────────────────────┘      │     │
│  │                      ▼                              │     │
│  │  ┌──────────────────────────────────────────┐      │     │
│  │  │  PostgreSQL Database                     │      │     │
│  │  │  - oauth_providers                       │      │     │
│  │  │  - oauth_credentials (encrypted)         │      │     │
│  │  │  - oauth_sessions                        │      │     │
│  │  └──────────────────────────────────────────┘      │     │
│  └────────────────────────────────────────────────────┘     │
│                      ▲                                       │
│                      │ HTTP + API Key Auth                   │
│                      │                                       │
│  ┌───────────────────┴───────────────────────────┐          │
│  │                                                 │          │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────┐│          │
│  │  │ Gmail MCP   │  │ Google Ads  │  │ Meta   ││          │
│  │  │ Server      │  │ MCP Server  │  │ MCP    ││          │
│  │  └──────┬──────┘  └──────┬──────┘  └───┬────┘│          │
│  │         │                 │              │     │          │
│  │         └─────────────────┴──────────────┘     │          │
│  │                     │                           │          │
│  │         ┌───────────▼──────────┐                │          │
│  │         │ mcp-auth-client      │                │          │
│  │         │ (Shared Package)     │                │          │
│  │         └──────────────────────┘                │          │
│  └─────────────────────────────────────────────────┘          │
│                                                               │
└───────────────────────────────┬───────────────────────────────┘
                                │ HTTPS/OAuth
                                ▼
                    ┌────────────────────────┐
                    │  OAuth Providers       │
                    │  - Google              │
                    │  - Microsoft           │
                    │  - Meta                │
                    └────────────────────────┘
```

---

## 🗄️ Database Schema

### Table 1: `oauth_providers`
```sql
CREATE TABLE oauth_providers (
    id VARCHAR(50) PRIMARY KEY,              -- 'google', 'microsoft', 'meta'
    client_id VARCHAR(255) NOT NULL,
    client_secret TEXT NOT NULL,             -- ENCRYPTED with Fernet
    auth_url VARCHAR(500),
    token_url VARCHAR(500),
    scopes JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Example data
INSERT INTO oauth_providers (id, client_id, client_secret, auth_url, token_url, scopes)
VALUES (
    'google',
    '123456789.apps.googleusercontent.com',
    'gAAAAABh...encrypted...',  -- Encrypted
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://oauth2.googleapis.com/token',
    '["https://www.googleapis.com/auth/gmail.send", "https://www.googleapis.com/auth/adwords"]'::jsonb
);
```

### Table 2: `oauth_credentials`
```sql
CREATE TABLE oauth_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id VARCHAR(255) NOT NULL,        -- EMAIL ADDRESS (e.g., 'alice@company.com')
    provider_id VARCHAR(50) NOT NULL REFERENCES oauth_providers(id),
    access_token TEXT NOT NULL,              -- ENCRYPTED with Fernet
    refresh_token TEXT,                      -- ENCRYPTED with Fernet
    token_expiry TIMESTAMP,
    scopes JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Ensure one credential per (email, provider) pair
    CONSTRAINT unique_user_provider UNIQUE(profile_id, provider_id),
    
    -- Validate email format
    CONSTRAINT valid_email CHECK (
        profile_id ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    )
);

CREATE INDEX idx_credentials_profile ON oauth_credentials(profile_id);
CREATE INDEX idx_credentials_expiry ON oauth_credentials(token_expiry);

-- Example data (after encryption)
INSERT INTO oauth_credentials (profile_id, provider_id, access_token, refresh_token, token_expiry, scopes)
VALUES (
    'alice@company.com',
    'google',
    'gAAAAABh...encrypted_access_token...',   -- Encrypted
    'gAAAAABh...encrypted_refresh_token...',  -- Encrypted
    NOW() + INTERVAL '1 hour',
    '["https://www.googleapis.com/auth/gmail.send"]'::jsonb
);
```

### Table 3: `oauth_sessions`
```sql
CREATE TABLE oauth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id VARCHAR(255) NOT NULL,        -- EMAIL ADDRESS
    provider_id VARCHAR(50) NOT NULL REFERENCES oauth_providers(id),
    state VARCHAR(255) UNIQUE NOT NULL,      -- CSRF token (random, single-use)
    status VARCHAR(20) DEFAULT 'pending',    -- 'pending', 'completed', 'failed'
    redirect_after TEXT,                     -- Optional: where to redirect after auth
    expires_at TIMESTAMP NOT NULL,           -- Session TTL (default: 15 minutes)
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT valid_status CHECK (status IN ('pending', 'completed', 'failed'))
);

CREATE INDEX idx_sessions_state ON oauth_sessions(state);
CREATE INDEX idx_sessions_status ON oauth_sessions(status, expires_at);

-- Auto-cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM oauth_sessions 
    WHERE expires_at < NOW() AND status = 'pending';
END;
$$ LANGUAGE plpgsql;
```

---

## 🔐 Encryption Implementation

### Encryption Strategy

**Method**: Fernet (Symmetric Encryption)
- **Algorithm**: AES-128 in CBC mode with HMAC-SHA256
- **Library**: `cryptography` (NIST approved)
- **Key Size**: 32 bytes (256 bits) base64-encoded
- **Features**: Built-in timestamp verification, key rotation support

**What Gets Encrypted**:
1. ✅ `oauth_credentials.access_token`
2. ✅ `oauth_credentials.refresh_token`
3. ✅ `oauth_providers.client_secret`

**What Does NOT Get Encrypted**:
- ❌ Email addresses (profile_id) - needed for indexing/querying
- ❌ Provider IDs - public information
- ❌ Timestamps - needed for queries
- ❌ Session states - temporary, not sensitive

### Key Management

**Primary Key**: Stored in environment variable
```bash
AUTH_GATEWAY_ENCRYPTION_KEY=wZq3t6v9y$B&E)H@McQfTjWnZr4u7x!A
```

**Optional Salt**: For additional key derivation
```bash
AUTH_GATEWAY_ENCRYPTION_KEY_SALT=random-32-char-salt-here
```

**Rotation Keys**: Old keys kept temporarily during rotation
```bash
AUTH_GATEWAY_ROTATION_KEYS=old-key-1,old-key-2
```

### Encryption Architecture

```python
# Encryption flow
User Email → Hash → Profile ID (email stored as-is)
OAuth Token → Fernet.encrypt() → Encrypted Token → PostgreSQL
PostgreSQL → Encrypted Token → Fernet.decrypt() → OAuth Token → MCP Server
```

---

## 📁 Project Structure

```
centralized-oauth-auth/
│
├── auth-gateway/                      # Main Auth Gateway application
│   ├── main.py                        # FastAPI application entrypoint
│   ├── config.py                      # Configuration & settings
│   ├── database.py                    # PostgreSQL connection & session
│   ├── encryption.py                  # Fernet encryption service
│   ├── models.py                      # SQLAlchemy models
│   ├── dependencies.py                # FastAPI dependencies
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py                    # /auth/* endpoints
│   │   └── health.py                  # /health endpoint
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── oauth_service.py           # OAuth flow logic
│   │   └── token_service.py           # Token refresh logic
│   │
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py                    # Pydantic request/response models
│   │   └── token.py
│   │
│   ├── scripts/
│   │   ├── generate_keys.py           # Generate encryption keys
│   │   ├── reencrypt_tokens.py        # Re-encrypt after key rotation
│   │   └── init_db.py                 # Initialize database
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_encryption.py
│   │   ├── test_auth_flow.py
│   │   └── test_token_refresh.py
│   │
│   ├── alembic/                       # Database migrations
│   │   ├── versions/
│   │   └── env.py
│   │
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
├── mcp-auth-client/                   # Shared client package
│   ├── mcp_auth_client/
│   │   ├── __init__.py
│   │   ├── client.py                  # AuthClient class
│   │   ├── decorators.py              # @require_auth decorator
│   │   ├── exceptions.py              # Custom exceptions
│   │   └── config.py
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_client.py
│   │   └── test_decorators.py
│   │
│   ├── setup.py
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── README.md
│
├── google-ads-mcp/                    # Google Ads MCP Server (modified)
│   ├── google_ads_server.py           # MODIFIED - uses mcp-auth-client
│   ├── requirements.txt               # ADD: mcp-auth-client
│   ├── .env.example                   # UPDATED environment vars
│   └── README.md                      # UPDATED with new auth flow
│
├── google-analytics-mcp/              # Google Analytics MCP (modified)
│   ├── server.py                      # MODIFIED - uses mcp-auth-client
│   ├── oauth/
│   │   └── google_auth.py             # DELETE - no longer needed
│   ├── requirements.txt               # ADD: mcp-auth-client
│   ├── .env.example                   # UPDATED environment vars
│   └── README.md                      # UPDATED with new auth flow
│
├── docker-compose.yml                 # Multi-container setup
├── docker-compose.prod.yml            # Production configuration
├── .env.example                       # Global environment template
├── .gitignore
└── README.md                          # Main project documentation
```

---

## 🔌 API Endpoints

### 1. Initialize OAuth Flow

**Endpoint**: `POST /auth/init`

**Purpose**: Start OAuth flow, generate auth URL

**Request**:
```json
{
  "provider": "google",
  "user_email": "alice@company.com",
  "scopes": ["https://www.googleapis.com/auth/gmail.send"]  // Optional, uses defaults
}
```

**Response**:
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&state=xyz123...",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2026-02-09T15:45:00Z"
}
```

**Headers Required**:
```
X-API-Key: your-gateway-api-key
Content-Type: application/json
```

---

### 2. OAuth Callback (Provider Redirect)

**Endpoint**: `GET /auth/callback/{provider}`

**Purpose**: Handle OAuth provider redirect after user consent

**Query Parameters**:
- `code`: Authorization code from provider
- `state`: CSRF token to validate session

**Example**:
```
GET /auth/callback/google?code=4/0AY0e-g7...&state=xyz123...
```

**Response**: HTML page with success message
```html
<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body>
  <h1>✅ Authentication Successful</h1>
  <p>You can now close this window and return to your assistant.</p>
</body>
</html>
```

**Backend Actions**:
1. Validate `state` matches session
2. Exchange `code` for tokens with provider
3. Encrypt tokens
4. Store in database
5. Update session status to 'completed'

---

### 3. Check Authentication Status

**Endpoint**: `GET /auth/status/{session_id}`

**Purpose**: Check if OAuth flow completed (polling endpoint)

**Response** (Pending):
```json
{
  "status": "pending",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2026-02-09T15:45:00Z"
}
```

**Response** (Completed):
```json
{
  "status": "completed",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_email": "alice@company.com",
  "provider": "google"
}
```

**Response** (Failed/Expired):
```json
{
  "status": "failed",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "error": "Session expired"
}
```

---

### 4. Get Access Token

**Endpoint**: `POST /auth/token`

**Purpose**: Get valid access token (auto-refreshes if expired)

**Request**:
```json
{
  "provider": "google",
  "user_email": "alice@company.com"
}
```

**Response** (Success):
```json
{
  "access_token": "ya29.a0AfH6SMBx...",
  "token_type": "Bearer",
  "expires_at": "2026-02-09T16:00:00Z",
  "scopes": ["https://www.googleapis.com/auth/gmail.send"]
}
```

**Response** (Not Authenticated):
```json
{
  "error": "not_authenticated",
  "message": "No credentials found for alice@company.com. Please authenticate.",
  "auth_required": true
}
```

**Response** (Refresh Failed - Need Re-auth):
```json
{
  "error": "refresh_failed",
  "message": "Refresh token expired. Please re-authenticate.",
  "auth_required": true
}
```

**Auto-Refresh Logic**:
```python
if token_expiry < now + 5 minutes:
    if refresh_token exists:
        try:
            new_token = refresh_with_provider()
            update_database()
            return new_token
        except RefreshError:
            return 401 with auth_required=True
    else:
        return 401 with auth_required=True
```

---

### 5. List Authorized Providers

**Endpoint**: `GET /auth/providers/{user_email}`

**Purpose**: Get list of providers user has authenticated with

**Response**:
```json
{
  "user_email": "alice@company.com",
  "providers": [
    {
      "provider": "google",
      "scopes": ["https://www.googleapis.com/auth/gmail.send"],
      "authenticated_at": "2026-02-09T14:30:00Z",
      "token_expires_at": "2026-02-09T16:00:00Z"
    },
    {
      "provider": "microsoft",
      "scopes": ["Mail.Send"],
      "authenticated_at": "2026-02-08T10:15:00Z",
      "token_expires_at": "2026-02-09T15:45:00Z"
    }
  ]
}
```

---

### 6. Revoke Authorization

**Endpoint**: `DELETE /auth/revoke`

**Purpose**: Delete stored credentials for a user

**Request**:
```json
{
  "provider": "google",
  "user_email": "alice@company.com"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Credentials revoked for alice@company.com (google)"
}
```

---

### 7. Health Check

**Endpoint**: `GET /health`

**Purpose**: Check if Auth Gateway is running

**Response**:
```json
{
  "status": "healthy",
  "database": "connected",
  "encryption": "operational",
  "version": "1.0.0",
  "timestamp": "2026-02-09T15:30:00Z"
}
```

---

## 🔧 MCP Server Integration

### Before (Current Implementation)

**google_ads_server.py**:
```python
# OLD CODE - Lines 209-349
def get_credentials(session_id):
    # Check if token file exists
    token_path = f"tokens/{session_id}.json"
    if os.path.exists(token_path):
        # Load and refresh if needed
        with open(token_path) as f:
            token_data = json.load(f)
        # ... refresh logic ...
    else:
        # Generate OAuth URL
        auth_url = generate_oauth_url()
        # Store pending flow
        pending_auth_flows[state] = {...}
        raise AuthRequiredException(auth_url)

# In each tool
@server.tool()
async def list_accounts():
    creds = get_credentials(target_session_id)
    headers = get_headers(creds)
    # ... API call ...
```

### After (New Implementation)

**google_ads_server.py**:
```python
# NEW CODE - Using mcp-auth-client
from mcp_auth_client import AuthClient, require_auth
from mcp_auth_client.exceptions import AuthRequiredException

# Initialize auth client
auth_client = AuthClient(
    gateway_url=os.getenv("AUTH_GATEWAY_URL"),
    api_key=os.getenv("AUTH_GATEWAY_API_KEY")
)

# In each tool - decorator handles auth automatically
@server.tool()
@require_auth(auth_client, provider="google")
async def list_accounts(user_email: str):
    """List Google Ads accounts for the user."""
    # Decorator ensures valid token or raises AuthRequiredException
    token = await auth_client.get_token("google", user_email)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Make API call
    response = await httpx.get(
        "https://googleads.googleapis.com/v13/customers:listAccessibleCustomers",
        headers=headers
    )
    return response.json()
```

**Key Changes**:
1. ❌ Remove local OAuth code (lines 209-349)
2. ❌ Remove `tokens/` directory and file handling
3. ❌ Remove global `pending_auth_flows` dict
4. ✅ Add `mcp-auth-client` import
5. ✅ Initialize `AuthClient` with gateway URL
6. ✅ Use `@require_auth` decorator on tools
7. ✅ Pass `user_email` parameter to tools

---

## 📦 mcp-auth-client Package

### Installation

```bash
cd mcp-auth-client
pip install -e .

# Or from repository
pip install git+https://github.com/your-org/mcp-auth-client.git
```

### Usage Example

```python
from mcp_auth_client import AuthClient
from mcp_auth_client.exceptions import AuthRequiredException

# Initialize
client = AuthClient(
    gateway_url="http://localhost:8000",
    api_key="your-api-key"
)

# Check if user is authenticated
is_authed = await client.is_authenticated("google", "alice@company.com")

if not is_authed:
    # Start OAuth flow
    auth_info = await client.init_oauth("google", "alice@company.com")
    print(f"Please visit: {auth_info['auth_url']}")
    
    # Wait for user to complete auth
    # (In MCP context, this returns to user with clickable link)
    raise AuthRequiredException(auth_info['auth_url'])

# Get token (auto-refreshes if needed)
token = await client.get_token("google", "alice@company.com")

# Use token
headers = {"Authorization": f"Bearer {token}"}
```

### Decorator Usage

```python
from mcp_auth_client import require_auth

@server.tool()
@require_auth(auth_client, provider="google")
async def send_email(user_email: str, to: str, subject: str, body: str):
    """Send email via Gmail API."""
    # If we reach here, authentication is guaranteed
    token = await auth_client.get_token("google", user_email)
    
    # Make API call
    # ...
```

**What the decorator does**:
1. Checks if user has valid credentials
2. If not authenticated → raises `AuthRequiredException` with auth URL
3. If token expired → auto-refreshes token
4. If refresh fails → raises `AuthRequiredException`
5. Only executes function if valid token available

---

## 🔄 OAuth Flow Sequence

```
User: "Send email to bob@example.com"
  │
  ├─> MCP Server: send_email tool called
  │     │
  │     ├─> Auth Client: get_token("google", "alice@company.com")
  │     │     │
  │     │     ├─> Auth Gateway: POST /auth/token
  │     │     │     │
  │     │     │     └─> Database: SELECT * FROM oauth_credentials
  │     │     │           WHERE profile_id = 'alice@company.com'
  │     │     │           │
  │     │     │           └─> NOT FOUND
  │     │     │
  │     │     └─> Return: 404 Not Authenticated
  │     │
  │     ├─> Auth Client: init_oauth("google", "alice@company.com")
  │     │     │
  │     │     ├─> Auth Gateway: POST /auth/init
  │     │     │     │
  │     │     │     ├─> Generate state = random_token()
  │     │     │     ├─> Create session in database
  │     │     │     └─> Generate auth_url with state
  │     │     │
  │     │     └─> Return: {auth_url, session_id}
  │     │
  │     └─> Raise AuthRequiredException(auth_url)
  │
  ├─> User sees: "🔐 Please authenticate: [Sign in with Google]"
  │
  ├─> User clicks link → Browser opens
  │     │
  │     ├─> Google OAuth consent screen
  │     │
  │     └─> User grants permissions
  │
  ├─> Google redirects to: /auth/callback/google?code=xxx&state=yyy
  │     │
  │     ├─> Auth Gateway validates state
  │     ├─> Exchange code for tokens
  │     ├─> Encrypt tokens
  │     ├─> Store in database
  │     ├─> Update session status = 'completed'
  │     └─> Show success page
  │
  ├─> User: "Done" or "Ready"
  │
  ├─> MCP Server: send_email tool called again
  │     │
  │     ├─> Auth Client: get_token("google", "alice@company.com")
  │     │     │
  │     │     ├─> Auth Gateway: POST /auth/token
  │     │     │     │
  │     │     │     ├─> Database: SELECT * FROM oauth_credentials
  │     │     │     │     └─> FOUND!
  │     │     │     ├─> Decrypt access_token
  │     │     │     ├─> Check expiry → Still valid
  │     │     │     └─> Return access_token
  │     │     │
  │     │     └─> Return: "ya29.a0AfH6SMBx..."
  │     │
  │     ├─> Make Gmail API call with token
  │     │
  │     └─> Email sent successfully!
  │
  └─> User: "✅ Email sent to bob@example.com"
```

---

## 🔄 Token Refresh Flow

```
MCP Server calls: get_token("google", "alice@company.com")
  │
  ├─> Auth Gateway: POST /auth/token
  │     │
  │     ├─> Database: SELECT * FROM oauth_credentials
  │     │     WHERE profile_id = 'alice@company.com'
  │     │     AND provider_id = 'google'
  │     │
  │     ├─> Decrypt access_token
  │     │
  │     ├─> Check: token_expiry < (now + 5 minutes)?
  │     │     │
  │     │     └─> YES - Token expiring soon or expired
  │     │           │
  │     │           ├─> Check: refresh_token exists?
  │     │           │     │
  │     │           │     └─> YES
  │     │           │           │
  │     │           │           ├─> Decrypt refresh_token
  │     │           │           │
  │     │           │           ├─> POST to Google token endpoint
  │     │           │           │     {
  │     │           │           │       grant_type: "refresh_token",
  │     │           │           │       refresh_token: "...",
  │     │           │           │       client_id: "...",
  │     │           │           │       client_secret: "..."
  │     │           │           │     }
  │     │           │           │
  │     │           │           ├─> Google returns:
  │     │           │           │     {
  │     │           │           │       access_token: "new_token",
  │     │           │           │       expires_in: 3600
  │     │           │           │     }
  │     │           │           │
  │     │           │           ├─> Encrypt new access_token
  │     │           │           │
  │     │           │           ├─> UPDATE oauth_credentials SET
  │     │           │           │     access_token = encrypted_new_token,
  │     │           │           │     token_expiry = now + 3600 seconds,
  │     │           │           │     updated_at = now
  │     │           │           │
  │     │           │           └─> Return new access_token
  │     │           │
  │     │           └─> NO refresh_token
  │     │                 │
  │     │                 └─> Return 401: Re-authentication required
  │     │
  │     └─> Return access_token to MCP Server
  │
  └─> MCP Server uses token for API call
```

---

## 🚀 Implementation Phases

### Phase 1: Foundation (Week 1)

#### Day 1-2: Auth Gateway Core
```bash
□ Create project structure
□ Set up FastAPI application
□ Configure PostgreSQL connection
□ Create SQLAlchemy models
□ Implement encryption service
□ Generate encryption keys
□ Create database migrations
```

**Deliverable**: Working Auth Gateway with database

**Verification**:
```bash
docker-compose up -d
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

#### Day 3-4: OAuth Endpoints
```bash
□ Implement POST /auth/init endpoint
□ Implement GET /auth/callback endpoint
□ Implement GET /auth/status endpoint
□ Implement POST /auth/token endpoint
□ Add token refresh logic
□ Add error handling
```

**Deliverable**: Complete OAuth flow endpoints

**Verification**:
```bash
# Test init
curl -X POST http://localhost:8000/auth/init \
  -H "X-API-Key: test-key" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","user_email":"test@example.com"}'
# Expected: {auth_url, session_id}
```

#### Day 5: Testing & Documentation
```bash
□ Unit tests for encryption
□ Integration tests for OAuth flow
□ API documentation (OpenAPI/Swagger)
□ README with setup instructions
```

---

### Phase 2: Client Package (Week 2)

#### Day 1-2: mcp-auth-client Core
```bash
□ Create package structure
□ Implement AuthClient class
□ Add get_token() method
□ Add init_oauth() method
□ Add is_authenticated() method
□ Add error handling
```

**Deliverable**: Installable Python package

**Verification**:
```bash
cd mcp-auth-client
pip install -e .
python -c "from mcp_auth_client import AuthClient; print('✓ Import works')"
```

#### Day 3-4: Decorator & Testing
```bash
□ Implement @require_auth decorator
□ Add custom exceptions
□ Unit tests for AuthClient
□ Integration tests with mock gateway
□ Documentation and examples
```

**Deliverable**: Production-ready client package

---

### Phase 3: MCP Integration (Week 3)

#### Day 1-3: Google Analytics MCP Migration
```bash
□ Install mcp-auth-client in project
□ Remove oauth/google_auth.py
□ Update server.py to use AuthClient
□ Replace all get_credentials() calls
□ Update all tool functions
□ Test with real Google Analytics API
□ Update documentation
```

**Deliverable**: Google Analytics MCP using centralized auth

**Verification**:
```bash
# Start Auth Gateway
docker-compose up -d

# Start Google Analytics MCP
cd google-analytics-mcp
python server.py

# Test in MCP client (e.g., Claude Desktop)
# Call list_properties tool → Should trigger OAuth flow
```

#### Day 4-5: Google Ads MCP Migration
```bash
□ Install mcp-auth-client in project
□ Remove local OAuth code (lines 209-349)
□ Update google_ads_server.py
□ Replace all authentication logic
□ Update all tool functions
□ Test with real Google Ads API
□ Update documentation
```

**Deliverable**: Google Ads MCP using centralized auth

---

### Phase 4: Production Deployment (Week 4)

#### Day 1-2: Docker & Infrastructure
```bash
□ Create production docker-compose.yml
□ Set up SSL/TLS certificates
□ Configure reverse proxy (nginx)
□ Set up monitoring (Prometheus/Grafana)
□ Configure logging (ELK stack)
□ Set up backups for PostgreSQL
```

#### Day 3-4: Security & Compliance
```bash
□ Security audit
□ Implement rate limiting
□ Add IP whitelisting
□ Set up key rotation schedule
□ Document security procedures
□ Create incident response plan
```

#### Day 5: Launch & Migration
```bash
□ Deploy to production server
□ Test end-to-end with real users
□ Monitor error logs
□ User communication about breaking changes
□ Support window for re-authentication
```

---

## 🔐 Environment Variables

### Auth Gateway (.env)

```bash
# ============================================
# Database Configuration
# ============================================
DATABASE_URL=postgresql://postgres:YOUR_STRONG_PASSWORD@db:5432/auth_gateway

# ============================================
# Encryption Configuration
# ============================================
# Generate with: python scripts/generate_keys.py
AUTH_GATEWAY_ENCRYPTION_KEY=wZq3t6v9y$B&E)H@McQfTjWnZr4u7x!A

# Optional: Salt for additional security (RECOMMENDED for production)
# ⚠️ WARNING: Never change this after initial setup!
AUTH_GATEWAY_ENCRYPTION_KEY_SALT=random-32-character-salt-here

# Optional: Rotation keys (during key rotation period only)
# AUTH_GATEWAY_ROTATION_KEYS=old-key-1,old-key-2

# ============================================
# API Security
# ============================================
# Generate with: python scripts/generate_keys.py --api-key
AUTH_GATEWAY_API_KEY=your-64-character-api-key-here

# ============================================
# Google OAuth Configuration
# ============================================
# Get from: https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID=123456789-abcdef.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/callback/google

# For production:
# GOOGLE_REDIRECT_URI=https://auth.yourdomain.com/callback/google

# ============================================
# Server Configuration
# ============================================
HOST=0.0.0.0
PORT=8000
ENVIRONMENT=development  # development | staging | production

# Session expiry for OAuth flows (minutes)
SESSION_EXPIRY_MINUTES=15

# Token refresh buffer (seconds before expiry)
TOKEN_REFRESH_BUFFER_SECONDS=300

# ============================================
# Logging & Monitoring
# ============================================
LOG_LEVEL=INFO  # DEBUG | INFO | WARNING | ERROR
LOG_FORMAT=json  # json | text
```

### MCP Servers (.env)

```bash
# ============================================
# Auth Gateway Connection
# ============================================
AUTH_GATEWAY_URL=http://localhost:8000
# For Docker internal network: http://auth-gateway:8000
# For production: https://auth.yourdomain.com

# Same API key as Auth Gateway
AUTH_GATEWAY_API_KEY=your-64-character-api-key-here

# ============================================
# Google Ads Specific (if needed)
# ============================================
GOOGLE_ADS_DEVELOPER_TOKEN=your-developer-token
GOOGLE_ADS_LOGIN_CUSTOMER_ID=1234567890

# ============================================
# OLD VARIABLES - DELETE THESE:
# ============================================
# GOOGLE_ADS_CLIENT_SECRET_PATH=...
# GOOGLE_ADS_TOKEN_PATH=...
# GOOGLE_ANALYTICS_OAUTH_CONFIG_PATH=...
# GOOGLE_ANALYTICS_TOKEN_PATH=...
```

---

## 🧪 Testing Strategy

### 1. Unit Tests

**Auth Gateway**:
```bash
cd auth-gateway
pytest tests/test_encryption.py -v
pytest tests/test_models.py -v
pytest tests/test_oauth_service.py -v
```

**mcp-auth-client**:
```bash
cd mcp-auth-client
pytest tests/test_client.py -v
pytest tests/test_decorators.py -v
```

### 2. Integration Tests

```bash
# Start services
docker-compose up -d

# Run integration tests
pytest tests/integration/ -v

# Test scenarios:
# - Complete OAuth flow
# - Token refresh
# - Concurrent requests
# - Error handling
# - Key rotation
```

### 3. Manual End-to-End Test

```bash
# Step 1: Start Auth Gateway
docker-compose up -d
docker-compose logs -f auth-gateway

# Step 2: Initialize OAuth
curl -X POST http://localhost:8000/auth/init \
  -H "X-API-Key: $(grep AUTH_GATEWAY_API_KEY .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "user_email": "your-test-email@example.com"
  }'

# Expected output:
# {
#   "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
#   "session_id": "550e8400-..."
# }

# Step 3: Open auth_url in browser
# Complete OAuth consent

# Step 4: Check status (poll until completed)
curl http://localhost:8000/auth/status/{session_id}

# Step 5: Get token
curl -X POST http://localhost:8000/auth/token \
  -H "X-API-Key: $(grep AUTH_GATEWAY_API_KEY .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "user_email": "your-test-email@example.com"
  }'

# Expected output:
# {
#   "access_token": "ya29.a0AfH6SMBx...",
#   "token_type": "Bearer",
#   "expires_at": "2026-02-09T16:00:00Z"
# }

# Step 6: Test MCP server
cd google-analytics-mcp
python server.py
# Call list_properties tool in MCP client
# Should work without additional auth prompts
```

### 4. Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load_test.py --host=http://localhost:8000

# Test scenarios:
# - 100 concurrent users
# - 1000 requests/second
# - Token refresh under load
```

---

## 🚨 Migration Plan (Breaking Change)

### Pre-Migration Checklist

```bash
□ Backup all existing token files
□ Document current MCP server configurations
□ Test Auth Gateway in staging environment
□ Generate all encryption keys
□ Update Google OAuth redirect URIs
□ Prepare user communication
□ Schedule maintenance window
```

### Migration Steps

#### Step 1: Backup (Day 0)
```bash
# Backup existing tokens
mkdir -p ~/mcp-tokens-backup-$(date +%Y%m%d)
cp -r google-ads-mcp/tokens ~/mcp-tokens-backup-$(date +%Y%m%d)/google-ads
cp -r google-analytics-mcp/tokens ~/mcp-tokens-backup-$(date +%Y%m%d)/google-analytics

# Backup environment files
cp google-ads-mcp/.env ~/mcp-tokens-backup-$(date +%Y%m%d)/google-ads.env
cp google-analytics-mcp/.env ~/mcp-tokens-backup-$(date +%Y%m%d)/google-analytics.env
```

#### Step 2: Deploy Auth Gateway (Day 0)
```bash
# Start Auth Gateway and database
cd centralized-oauth-auth
docker-compose up -d auth-gateway db

# Wait for healthy status
while ! curl -s http://localhost:8000/health | grep healthy; do
  echo "Waiting for Auth Gateway..."
  sleep 2
done

echo "✓ Auth Gateway is healthy"
```

#### Step 3: Update MCP Servers (Day 1)
```bash
# Google Analytics MCP
cd google-analytics-mcp
git pull origin feature/centralized-auth
pip install -r requirements.txt  # Includes mcp-auth-client
cp .env.example .env
# Edit .env with AUTH_GATEWAY_URL and AUTH_GATEWAY_API_KEY

# Google Ads MCP
cd google-ads-mcp
git pull origin feature/centralized-auth
pip install -r requirements.txt  # Includes mcp-auth-client
cp .env.example .env
# Edit .env with AUTH_GATEWAY_URL and AUTH_GATEWAY_API_KEY
```

#### Step 4: User Communication (Day 1)
```markdown
# Email/Slack Notification Template

Subject: Action Required: Re-authenticate MCP Servers

Hi Team,

We've upgraded our MCP servers to use centralized authentication. This improves security and makes managing OAuth tokens easier.

**Action Required:**
When you next use Google Ads or Google Analytics MCP tools, you'll be prompted to re-authenticate:

1. Click the "Sign in with Google" link
2. Complete OAuth consent
3. Return to the assistant and say "done"

This is a one-time process per account.

**Timeline:**
- Old authentication: Disabled on [DATE]
- New authentication: Available now

**Need Help?**
Contact: [SUPPORT EMAIL]

Thanks!
[YOUR NAME]
```

#### Step 5: Restart MCP Servers (Day 1)
```bash
# Restart with new code
pm2 restart google-analytics-mcp
pm2 restart google-ads-mcp

# Or if using systemd
sudo systemctl restart google-analytics-mcp
sudo systemctl restart google-ads-mcp
```

#### Step 6: Monitor (Day 1-3)
```bash
# Watch logs
docker-compose logs -f auth-gateway
tail -f google-analytics-mcp/logs/server.log
tail -f google-ads-mcp/logs/server.log

# Check database
docker exec -it auth-gateway-db psql -U postgres -d auth_gateway \
  -c "SELECT profile_id, provider_id, created_at FROM oauth_credentials ORDER BY created_at DESC LIMIT 10;"
```

#### Step 7: Cleanup (Day 7)
```bash
# After 1 week of successful operation
# Remove old token files (keep backup)
rm -rf google-ads-mcp/tokens/*
rm -rf google-analytics-mcp/tokens/*

# Update .gitignore to prevent old token files
echo "tokens/" >> google-ads-mcp/.gitignore
echo "tokens/" >> google-analytics-mcp/.gitignore
```

---

## 🔄 Key Rotation Procedure

### Schedule
- **Regular Rotation**: Every 90 days
- **Emergency Rotation**: Immediately if compromise suspected

### Rotation Steps

```bash
# Step 1: Generate new key
cd auth-gateway
python scripts/generate_keys.py --rotate

# Output:
# Current key becomes: AUTH_GATEWAY_ROTATION_KEYS
# New primary key: AUTH_GATEWAY_ENCRYPTION_KEY=NEW_KEY_HERE

# Step 2: Update .env
# Before:
AUTH_GATEWAY_ENCRYPTION_KEY=old-key-here

# After:
AUTH_GATEWAY_ENCRYPTION_KEY=new-key-here
AUTH_GATEWAY_ROTATION_KEYS=old-key-here

# Step 3: Restart Auth Gateway (zero downtime)
docker-compose restart auth-gateway
# Gateway can now decrypt with old key, encrypt with new key

# Step 4: Test that decryption still works
curl -X POST http://localhost:8000/auth/token \
  -H "X-API-Key: $AUTH_GATEWAY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","user_email":"test@example.com"}'
# Should return token successfully

# Step 5: Re-encrypt all tokens (background process)
docker exec -it auth-gateway python scripts/reencrypt_tokens.py
# This decrypts with old key, re-encrypts with new key

# Step 6: Verify re-encryption
docker exec -it auth-gateway python scripts/reencrypt_tokens.py --dry-run
# Should show all tokens processed successfully

# Step 7: Remove old key (after 48 hours)
# Update .env:
AUTH_GATEWAY_ENCRYPTION_KEY=new-key-here
# AUTH_GATEWAY_ROTATION_KEYS=  # Remove this line

# Step 8: Restart
docker-compose restart auth-gateway
```

---

## 📊 Monitoring & Alerting

### Metrics to Track

1. **Authentication Success Rate**
```sql
-- Daily auth success rate
SELECT 
  DATE(created_at) as date,
  status,
  COUNT(*) as count
FROM oauth_sessions
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at), status
ORDER BY date DESC;
```

2. **Token Refresh Success Rate**
```sql
-- Token refresh activity
SELECT 
  DATE(updated_at) as date,
  COUNT(*) as refresh_count
FROM oauth_credentials
WHERE updated_at > created_at
  AND updated_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(updated_at)
ORDER BY date DESC;
```

3. **Encryption Performance**
```python
# Add to auth-gateway/main.py
import time
import prometheus_client

encryption_duration = prometheus_client.Histogram(
    'encryption_duration_seconds',
    'Time spent encrypting tokens'
)

@encryption_duration.time()
def encrypt_token(token):
    return encryptor.encrypt(token)
```

### Alert Rules

```yaml
# alerts.yml (for Prometheus Alertmanager)
groups:
  - name: auth_gateway
    rules:
      - alert: HighAuthFailureRate
        expr: rate(oauth_session_failed_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High OAuth failure rate detected"
      
      - alert: DatabaseConnectionDown
        expr: up{job="auth-gateway-db"} == 0
        for: 1m
        annotations:
          summary: "Auth Gateway database is down"
      
      - alert: EncryptionErrors
        expr: rate(encryption_error_total[5m]) > 0
        for: 5m
        annotations:
          summary: "Encryption errors detected"
```

---

## 🛡️ Security Best Practices

### 1. Key Management

✅ **DO**:
- Generate keys using cryptographically secure methods
- Store keys in environment variables (or secrets manager)
- Use different keys per environment (dev/staging/prod)
- Rotate keys regularly (every 90 days)
- Back up keys in encrypted password manager
- Audit key access logs

❌ **DON'T**:
- Commit keys to Git
- Share keys via email/Slack/SMS
- Reuse keys across projects
- Store keys in plaintext files
- Give key access to non-ops personnel

### 2. Database Security

```sql
-- Use strong passwords
ALTER USER postgres WITH PASSWORD 'StrongP@ssw0rd!2026';

-- Restrict network access
# postgresql.conf
listen_addresses = 'localhost'

# pg_hba.conf
host    auth_gateway    postgres    127.0.0.1/32    md5

-- Enable SSL
ssl = on
ssl_cert_file = '/path/to/cert.pem'
ssl_key_file = '/path/to/key.pem'
```

### 3. API Security

```python
# Rate limiting
from slowapi import Limiter

limiter = Limiter(key_func=lambda: request.client.host)

@app.post("/auth/init")
@limiter.limit("10/minute")
async def init_auth(...):
    pass

# API key validation
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.AUTH_GATEWAY_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key

# CORS configuration
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Not "*"
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["X-API-Key"],
)
```

### 4. Logging & Auditing

```python
# Structured logging
import structlog

logger = structlog.get_logger()

@app.post("/auth/token")
async def get_token(user_email: str, provider: str):
    logger.info(
        "token_requested",
        user_email=user_email,
        provider=provider,
        timestamp=datetime.utcnow(),
        request_id=request.state.request_id
    )
    # ... rest of logic ...
```

---

## 📚 Documentation Checklist

### For Developers
- [ ] Architecture diagram
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Database schema documentation
- [ ] Setup instructions
- [ ] Testing guide
- [ ] Deployment guide

### For Operations
- [ ] Installation guide
- [ ] Configuration guide
- [ ] Key rotation procedure
- [ ] Backup & restore procedure
- [ ] Monitoring setup
- [ ] Incident response playbook

### For End Users
- [ ] Authentication guide
- [ ] Troubleshooting guide
- [ ] FAQ

---

## ✅ Final Implementation Checklist

### Pre-Implementation
- [ ] Review and approve architecture
- [ ] Confirm PostgreSQL database choice
- [ ] Confirm email-based profile_id
- [ ] Generate encryption keys
- [ ] Set up development environment
- [ ] Create project repositories

### Phase 1: Auth Gateway (Week 1)
- [ ] Create project structure
- [ ] Implement encryption service
- [ ] Create database models
- [ ] Implement OAuth endpoints
- [ ] Add token refresh logic
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Document API

### Phase 2: mcp-auth-client (Week 2)
- [ ] Create package structure
- [ ] Implement AuthClient class
- [ ] Implement @require_auth decorator
- [ ] Write tests
- [ ] Publish to PyPI (optional)
- [ ] Write documentation

### Phase 3: MCP Integration (Week 3)
- [ ] Migrate Google Analytics MCP
- [ ] Test Google Analytics integration
- [ ] Migrate Google Ads MCP
- [ ] Test Google Ads integration
- [ ] Update all documentation

### Phase 4: Deployment (Week 4)
- [ ] Set up production infrastructure
- [ ] Configure SSL/TLS
- [ ] Set up monitoring
- [ ] Set up backups
- [ ] Security audit
- [ ] Deploy to production
- [ ] User communication
- [ ] Support window

### Post-Deployment
- [ ] Monitor logs for errors
- [ ] Track authentication metrics
- [ ] Gather user feedback
- [ ] Schedule key rotation
- [ ] Document lessons learned

---

## 🎓 Key Learnings & Best Practices

1. **Email-based Identity**: Using emails as profile_id is user-friendly and naturally unique
2. **Encryption is Non-negotiable**: Always encrypt sensitive tokens at rest
3. **Key Rotation**: Plan for key rotation from day one
4. **Clean Start Migration**: Re-authentication is often simpler than token migration
5. **Decorator Pattern**: `@require_auth` makes MCP integration clean and simple
6. **Auto-refresh**: Implement automatic token refresh for better UX
7. **Comprehensive Logging**: Log everything for debugging and auditing
8. **Zero Downtime**: Use rotation keys to avoid downtime during key rotation

---

## 📞 Support & Resources

### Internal Resources
- **Auth Gateway Repository**: [Link]
- **mcp-auth-client Repository**: [Link]
- **Documentation**: [Link]
- **Slack Channel**: #mcp-auth-gateway

### External Resources
- **OAuth 2.0 Spec**: https://oauth.net/2/
- **Fernet Specification**: https://github.com/fernet/spec
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **SQLAlchemy Documentation**: https://docs.sqlalchemy.org/

---

## 🎯 Success Criteria

### Technical
- ✅ All MCP servers use centralized auth
- ✅ Zero OAuth code duplication
- ✅ 99.9% authentication success rate
- ✅ < 100ms token retrieval latency
- ✅ Zero plaintext tokens in database

### Operational
- ✅ Automated key rotation process
- ✅ Comprehensive monitoring
- ✅ Clear incident response procedures
- ✅ < 1 hour to add new OAuth provider

### User Experience
- ✅ One-click OAuth authentication
- ✅ Transparent token refresh
- ✅ Clear error messages
- ✅ Minimal re-authentication required

---

**Implementation Status**: Ready to Begin  
**Next Action**: Start Phase 1 - Auth Gateway Foundation  
**Estimated Completion**: 4 weeks from start date

**Questions or concerns?** Review this document thoroughly, then begin implementation!
