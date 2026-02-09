# Google Analytics MCP Server Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy mcp-auth-client
COPY ../../mcp-auth-client /app/mcp-auth-client
RUN pip install --no-cache-dir -e /app/mcp-auth-client

# Copy application
COPY server_centralized.py .
COPY .env.example .env.example

# Create non-root user
RUN useradd -m -u 1000 mcpuser
RUN chown -R mcpuser:mcpuser /app
USER mcpuser

EXPOSE 8000

CMD ["python", "server_centralized.py", "--http"]
