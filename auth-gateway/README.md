# Auth Gateway

Centralized OAuth authentication service for MCP servers. Built with FastAPI and PostgreSQL.

## Features

- 🔐 **Centralized Token Management**: One gateway for all MCP servers
- 📧 **Email-based User Identification**: Uses email addresses as unique identifiers
- 🔒 **Fernet Encryption**: AES-128-CBC + HMAC-SHA256 for token encryption
- 🔄 **Key Rotation**: Zero-downtime encryption key rotation support
- 🐘 **PostgreSQL**: Scalable, production-ready storage
- 🐳 **Docker Ready**: Easy containerized deployment

## Quick Start

### 1. Generate Keys

```bash
cd auth-gateway
python scripts/generate_keys.py
```

Copy the generated keys to your `.env` file.

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your values
```

### 3. Start Services

```bash
# With Docker Compose (recommended)
docker-compose up -d

# Or run directly
pip install -r requirements.txt
python main.py
```

### 4. Initialize Database

```bash
# With Docker
docker exec auth-gateway python scripts/init_db.py --seed

# Or directly
python scripts/init_db.py --seed
```

### 5. Verify

```bash
curl http://localhost:8000/health
# {"status": "healthy", "database": "connected", "encryption": "operational"}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/init` | POST | Start OAuth flow |
| `/auth/callback/{provider}` | GET | Handle OAuth redirect |
| `/auth/status/{session_id}` | GET | Check auth completion |
| `/auth/token` | POST | Get/refresh access token |
| `/auth/providers/{email}` | GET | List user's providers |
| `/auth/revoke` | DELETE | Revoke credentials |
| `/health` | GET | Health check |

## Environment Variables

See [.env.example](.env.example) for all configuration options.

**Required:**
- `AUTH_GATEWAY_ENCRYPTION_KEY` - Fernet encryption key
- `AUTH_GATEWAY_API_KEY` - API key for MCP servers
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret

## Key Rotation

```bash
# 1. Generate new key and update .env
python scripts/generate_keys.py --rotate

# 2. Restart gateway (can decrypt old, encrypts new)
docker-compose restart auth-gateway

# 3. Re-encrypt all tokens
docker exec auth-gateway python scripts/reencrypt_tokens.py

# 4. Remove old key from .env after 48 hours
```
