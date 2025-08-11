"""Essential tests for TinyMCP - covers core functionality only."""

import pytest
import json
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinymcp import create_mcp_router, mcp_tool


class TestTinyMCP:
    """Essential tests covering the core TinyMCP functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create FastAPI app with MCP router
        self.app = FastAPI()
        self.router = create_mcp_router(name="Test Server", version="1.0.0")
        self.app.include_router(self.router)
        self.client = TestClient(self.app)

        # Register test tools
        @mcp_tool(name="echo", description="Echo input")
        def echo_tool(message: str) -> str:
            return message

        @mcp_tool(name="add", description="Add two numbers")
        def add_tool(a: int, b: int) -> int:
            return a + b

        @mcp_tool(name="structured", description="Return structured output")
        def structured_tool(name: str) -> dict:
            return {
                "content": [{"type": "text", "text": f"Hello {name}"}],
                "structured": {"greeting": f"Hello {name}"}
            }

    def test_mcp_initialize(self):
        """Test MCP initialize endpoint."""
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["result"]["protocolVersion"] == "2025-06-18"
        assert data["result"]["serverInfo"]["name"] == "Test Server"

    def test_tools_list(self):
        """Test tools/list endpoint returns registered tools."""
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })
        
        assert response.status_code == 200
        tools = response.json()["result"]["tools"]
        tool_names = [tool["name"] for tool in tools]
        
        assert "echo" in tool_names
        assert "add" in tool_names
        assert "structured" in tool_names

    def test_tool_execution(self):
        """Test basic tool execution."""
        # Test echo tool
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "Hello"}}
        })
        
        assert response.status_code == 200
        result = response.json()["result"]
        assert json.loads(result["content"][0]["text"]) == "Hello"

        # Test add tool
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 5, "b": 3}}
        })
        
        assert response.status_code == 200
        result = response.json()["result"]
        assert json.loads(result["content"][0]["text"]) == 8

    def test_structured_output(self):
        """Test structured output support (MCP 2025-06-18 feature)."""
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "structured", "arguments": {"name": "Alice"}}
        })
        
        assert response.status_code == 200
        result = response.json()["result"]
        
        # Should have both content and structured fields
        assert "content" in result
        assert "structured" in result
        assert result["structured"]["greeting"] == "Hello Alice"

    def test_error_handling(self):
        """Test error handling for invalid requests."""
        # Test nonexistent tool
        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}}
        })
        
        assert response.status_code == 200
        assert "error" in response.json()

        # Test invalid request format
        response = self.client.post("/mcp", json={"invalid": "request"})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_async_tool(self):
        """Test that async tools work correctly."""
        @mcp_tool(name="async_test")
        async def async_tool(value: int) -> int:
            return value * 2

        response = self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "async_test", "arguments": {"value": 21}}
        })
        
        assert response.status_code == 200
        result = json.loads(response.json()["result"]["content"][0]["text"])
        assert result == 42


class TestToolRegistry:
    """Test core registry functionality."""

    def test_tool_registration_and_execution(self):
        """Test the complete tool registration and execution flow."""
        from tinymcp import ToolRegistry
        
        registry = ToolRegistry()

        @registry.tool(name="test_func", description="A test function")
        def test_func(x: int, y: str = "default") -> dict:
            return {"x": x, "y": y}

        # Check registration
        assert "test_func" in registry.get_tool_names()
        
        # Check schema
        schema = registry.get_tools_schema()[0]
        assert schema["name"] == "test_func"
        assert schema["description"] == "A test function"
        assert "x" in schema["inputSchema"]["required"]
        assert "y" not in schema["inputSchema"]["required"]  # Has default

    def test_serialization(self):
        """Test that common objects are serialized properly."""
        from tinymcp import ToolRegistry
        
        registry = ToolRegistry()
        
        # Test dict serialization (already JSON-safe)
        result = registry._serialize({"key": "value", "num": 42})
        assert result == {"key": "value", "num": 42}
        
        # Test list serialization (already JSON-safe)
        result = registry._serialize([1, 2, {"nested": "data"}])
        assert result == [1, 2, {"nested": "data"}]
        
        # Test object with __dict__ serialization
        class SimpleObject:
            def __init__(self, value):
                self.value = value
        
        obj = SimpleObject("test")
        result = registry._serialize(obj)
        assert result == {"value": "test"}  # Should serialize __dict__ attributes
