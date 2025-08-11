#!/usr/bin/env python3
"""
Simple TinyMCP example - run with: uv run python example.py
"""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from registry import mcp_tool
from router import create_mcp_router
import uvicorn

# Define some tools
@mcp_tool(name="hello", description="Say hello")
def hello(name: str = "World") -> str:
    return f"Hello, {name}!"

@mcp_tool(name="add", description="Add two numbers")
def add(a: int, b: int) -> int:
    return a + b

# Create FastAPI app
app = FastAPI(title="TinyMCP Example")
app.include_router(create_mcp_router(name="Example Server"))

if __name__ == "__main__":
    print("🚀 TinyMCP Example Server")
    print("📡 http://localhost:8000/mcp")
    uvicorn.run(app, host="0.0.0.0", port=8000)
