# TinyMCP

A lightweight MCP router for FastAPI.

## Quick Start

```python
from tinymcp import create_mcp_router, mcp_tool

@mcp_tool(description="Get current time")
def get_time() -> str:
    from datetime import datetime
    return datetime.now().isoformat()

@mcp_tool(description="Get user data with structured output")
def get_user_data():
    return {
        "content": [{"type": "text", "text": "User data retrieved"}],
        "structured": {"user_id": 123, "email": "user@example.com"}
    }

# Add to FastAPI
app.include_router(create_mcp_router(name="My App"))

# Custom prefix (default: "/mcp")
app.include_router(create_mcp_router(name="My App", prefix="/my-mcp"))
```

## Installation

```bash
git clone https://github.com/grab/tinymcp.git
cd tinymcp
pip install -e .
```

## Quick Demo

```bash
# Clone and run example
git clone https://github.com/grab/tinymcp.git
cd tinymcp

uv run python docs/sample_server/simple_fastapi_server.py
```

## Note on Authentication

Authentication has been intentionally left out of TinyMCP to keep it... tiny. Any auth that can be setup with FastAPI in general can be setup with this. However, for MCP server to interact with most MCP clients like cursor, several specific configurations, endpoints etc. are required. If you have an existing OAuth mechanism in your FastAPI server, it is quite easy to make it work for the TinyMCP server as well. See [oauth_integration_guide.md](./auth_info/oauth_integration_guide.md) for a complete setup guide.
