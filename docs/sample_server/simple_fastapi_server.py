import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fastapi import FastAPI
from tinymcp import mcp_tool, create_mcp_router

# Define some tools
@mcp_tool(name="hello", description="Say hello")
def hello(name: str = "World") -> str:
    return f"Hello, {name}!"

@mcp_tool(name="add", description="Add two numbers")
def add(a: int, b: int) -> int:
    return a + b

# Create FastAPI app and add TinyMCP router
app = FastAPI(title="TinyMCP Simple Server")
app.include_router(create_mcp_router(name="Simple Server"))

if __name__ == "__main__":
    import uvicorn
    print("🚀 TinyMCP Example Server")
    print("📡 http://localhost:8000/mcp")
    uvicorn.run(app, host="0.0.0.0", port=8000)