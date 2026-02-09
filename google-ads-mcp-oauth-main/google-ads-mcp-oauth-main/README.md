# Google Ads MCP Server

A robust **Model Context Protocol (MCP)** server that connects AI agents (like Claude Desktop) to the **Google Ads API**. 

This server allows your AI assistant to analyze campaign performance, review ad creatives, download image assets, and execute complex queries using natural language.

## 🌟 Key Features

*   **Central Analytics Router**: A smart entry point (`analytics_router`) that translates natural language intent (e.g., "how are my ads doing?") into precise Google Ads queries.
*   **OAuth2 Authentication**: Secure, user-based authentication flow with automatic token refreshing and session management.
*   **Performance Analysis**: Fetch metrics for campaigns, ad groups, and ads with custom lookback windows.
*   **Creative Auditing**: Retrieve and analyze ad headlines, descriptions, and final URLs.
*   **Asset Management**: Search, list, and **download** image assets directly from your account.
*   **Advanced Querying**: Execute raw **GAQL** (Google Ads Query Language) for unlimited flexibility.
*   **Docker Ready**: Fully containerized for easy deployment.

---

## 🛠️ Prerequisites

Before running the server, you need:

1.  **Google Ads Developer Token**: Apply for one in your Manager Account (MCC).
2.  **Google Cloud Project**: Enable the "Google Ads API".
3.  **OAuth Credentials**: Create an "OAuth 2.0 Client ID" (Desktop App) and download the `client_secret.json`.

---

## 🚀 Installation & Setup

### Option 1: Docker (Recommended)

1.  **Clone the repository**:
    ```bash
    git clone <your-repo-url>
    cd google-ads-mcp
    ```

2.  **Prepare Credentials**:
    *   Create a folder named `Google_Creds` in the project root.
    *   Place your downloaded `client_secret.json` inside it.

3.  **Configure Environment**:
    *   Copy `.env.example` to `.env`:
        ```bash
        cp .env.example .env
        ```
    *   Edit `.env` and fill in your details:
        ```ini
        GOOGLE_ADS_DEVELOPER_TOKEN=INSERT_YOUR_TOKEN_HERE
        GOOGLE_ADS_CLIENT_SECRET_PATH=./Google_Creds/client_secret.json
        GOOGLE_ADS_TOKEN_PATH=./Google_Creds/tokens/default.json
        ```

4.  **Run with Docker Compose**:
    ```bash
    docker-compose up -d --build
    ```

### Option 2: Local Python Environment

1.  **create a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment** (same as Docker step 3).

4.  **Run the Server**:
    ```bash
    python google_ads_server.py
    ```

---

## 🔐 Authentication Flow

The first time you (or the AI) attempts to access data, the server will trigger an OAuth flow.

1.  The AI will report: *"AUTHENTICATION REQUIRED. Please visit [URL]..."*
2.  **Click the link** to open your browser.
3.  Log in with your Google Account and allow the permissions.
4.  You will be redirected to the success page.
5.  Ask the AI to **try the request again**. It will now succeed.

*Note: Tokens are saved persistently in `Google_Creds/tokens/`.*

---

## 🔌 Connecting to Claude Desktop

Add this to your `claude_desktop_config.json`:

### Docker
```json
{
  "mcpServers": {
    "google-ads": {
      "command": "docker",
      "args": ["exec", "-i", "google_ads_mcp", "python", "google_ads_server.py", "--mode", "stdio"]
    }
  }
}
```

### Local
```json
{
  "mcpServers": {
    "google-ads": {
      "command": "python",
      "args": ["/absolute/path/to/google_ads_server.py"]
    }
  }
}
```

---

## 🧰 Available Tools for the AI

The server exposes several tools. The AI knows when to use them, but here is a summary:

| Tool | Description |
| :--- | :--- |
| **`analytics_router`** | **The Main Tool**. Handles requests like "show campaign performance", "list ads", "check creatives". |
| `list_accounts` | Lists all accessible Google Ads customer IDs. |
| `execute_gaql_query` | Runs a standard GAQL query.Internal tool (prefer router). |
| `run_gaql` | Runs an *arbitrary* GAQL query with custom formatting (JSON/CSV). |
| `get_ad_creatives` | Fetches ad copy (headlines, descriptions) for review. |
| `get_image_assets` | Lists image assets available in the account. |
| `download_image_asset` | Downloads a high-res image asset to the local disk. |
| `get_asset_usage` | Maps where an asset is used (which campaigns/ad groups). |

---

## 🛡️ Security Notes

*   **Credentials**: Never commit `client_secret.json` or `token.json` to git. The `.gitignore` is pre-configured to exclude the `Google_Creds/` directory.
*   **Docker**: The `docker-compose.yml` mounts `Google_Creds` as a volume, ensuring your login session persists even if you rebuild the container.

---

## 📄 License

[MIT License](LICENSE)
