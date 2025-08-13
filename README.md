# TinyMCP

A lightweight MCP router for FastAPI.

## Installation
### Install directly:
```bash
uv pip install --no-cache \
  --index-url "https://gitlab.myteksi.net/api/v4/projects/34156/packages/pypi/simple/" \
  "tinymcp"
```


### Adding as a dependency in Python Projects:
- For Poetry projects:
```toml
[tool.poetry.dependencies]
tinymcp = {version = "^0.1.0", source = "grab-tinymcp"}

[[tool.poetry.source]]
name = "grab-tinymcp"
url = "https://gitlab.myteksi.net/api/v4/projects/34156/packages/pypi/simple"
priority = "supplemental"
```

- For UV projects:
```toml
[project]
dependencies = ["tinymcp>=0.1.0"]

[tool.uv.index]
grab-tinymcp = { url = "https://gitlab.myteksi.net/api/v4/projects/34156/packages/pypi/simple" }

[tool.uv.sources]
tinymcp = { index = "grab-tinymcp" }
```


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

## Quick Demo
Once you have this repo cloned, from root, run the following (install the missing dev dependencies as required)

```bash
uv run python docs/sample_server/simple_fastapi_server.py
```

## Note on Authentication

Authentication has been intentionally left out of TinyMCP to keep it... tiny. Any auth that can be setup with FastAPI in general can be setup with this. However, for MCP server to interact with most MCP clients like cursor, several specific configurations, endpoints etc. are required. If you have an existing OAuth mechanism in your FastAPI server, it is quite easy to make it work for the TinyMCP server as well. See [oauth_integration_guide.md](./auth_info/oauth_integration_guide.md) for a complete setup guide.
