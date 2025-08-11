# TinyMCP

A lightweight MCP router for FastAPI. Supports MCP 2025-06-18 specification.

## Quick Start

```python
from tinymcp import create_mcp_router, mcp_tool

@mcp_tool(description="Get current time")
def get_time() -> str:
    from datetime import datetime
    return datetime.now().isoformat()

# Structured output (new in 2025-06-18)
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
# Install from PyPI (once published)
pip install tinymcp

# Or install from source
git clone https://github.com/grab/tinymcp.git
cd tinymcp
pip install -e .
```

## Quick Demo

```bash
# Clone and run example
git clone https://github.com/grab/tinymcp.git
cd tinymcp

# Run with uv
uv run python example.py

# Or install first
uv pip install uvicorn
python example.py
```

## Features

- ✅ **Simple**: Just add `@mcp_tool` decorator to functions
- ✅ **Fast**: Built on FastAPI with automatic async support
- ✅ **Modern**: Full MCP 2025-06-18 specification support
- ✅ **Flexible**: Zero auth dependencies - bring your own auth
- ✅ **Smart**: Automatic JSON schema generation from function signatures
- ✅ **Compatible**: Works with Cursor and other MCP clients

## Examples

See the [`examples/`](./examples/) directory for:

- **Simple Demo** (`examples/simple_demo.py`) - Basic functionality
- **Sample Server** (`examples/sample-server/`) - Full-featured MCP server with multiple tools
- **Advanced Demo** (`examples/sample-server/tinymcp_demo.py`) - Comprehensive demonstration

## Authentication

Authentication has been intentionally left out of TinyMCP to keep it... tiny. Any auth that can be setup with FastAPI in general can be setup with this. However, for MCP server to interact with most MCP clients like cursor, several specific configurations, endpoints etc. are required. If you have an existing OAuth mechanism in your FastAPI server, it is quite easy to make it work for the TinyMCP server as well. See [oauth_integration_guide.md](./auth_info/oauth_integration_guide.md) for a complete setup guide.

## Publishing to PyPI

```bash
# Build the package
uv build

# Publish to Test PyPI first
uv publish --publish-url https://test.pypi.org/legacy/

# Publish to production PyPI
uv publish
```

## Testing

```bash
# Run tests
pytest tests/

# Or with uv
uv run pytest tests/
```