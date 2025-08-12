import json
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from tinymcp.registry import get_default_registry


def create_mcp_router(
    name: str = "TinyMCP", version: str = "0.1.0", prefix: str = "/mcp", logger=None
) -> APIRouter:
    """
    Create a FastAPI router with MCP protocol endpoints.

    This creates the core MCP JSON-RPC endpoint. For authentication:
    1. Add OAuth discovery endpoints (see OAUTH_INTEGRATION.md)
    2. Add authentication middleware to validate tokens
    3. Access user context in tools via request.state.user

    Args:
        name: Server name returned in MCP responses
        version: Server version returned in MCP responses
        prefix: URL prefix for MCP endpoints (default: "/mcp")
        logger: Optional logger function for debug messages

    Returns:
        FastAPI APIRouter with MCP protocol endpoints
    """

    router = APIRouter()
    registry = get_default_registry()
    log = logger or (lambda msg: None)

    async def handle_message(message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle single JSON-RPC message."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": name, "version": version},
                }

            elif method == "tools/list":
                result = {"tools": registry.get_tools_schema()}

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                if not tool_name:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32602, "message": "Missing tool name"},
                    }

                tool_result = await registry.call_tool(tool_name, arguments)

                if isinstance(tool_result, dict) and "structured" in tool_result:
                    result = {
                        "content": tool_result.get(
                            "content",
                            [{"type": "text", "text": json.dumps(tool_result)}],
                        ),
                        "isError": False,
                    }
                    if "structured" in tool_result:
                        result["structured"] = tool_result["structured"]
                else:
                    result = {
                        "content": [{"type": "text", "text": json.dumps(tool_result)}],
                        "isError": False,
                    }

            else:
                result = {}  # Default empty response

            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        except Exception as e:
            log(f"Error handling {method}: {e}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32000, "message": str(e)},
            }

    @router.post(prefix)
    async def mcp_endpoint(request: Request) -> JSONResponse:
        """
        Main MCP endpoint - handles JSON-RPC messages.
        """
        body = await request.json()

        protocol_header = request.headers.get("MCP-Protocol-Version")
        if protocol_header and protocol_header != "2025-06-18":
            return JSONResponse(
                {"error": f"Unsupported protocol version: {protocol_header}"},
                status_code=400,
            )

        if isinstance(body, dict) and "method" in body:
            response = await handle_message(body)
            return JSONResponse(response)

        else:
            return JSONResponse({"error": "Invalid MCP request"}, status_code=400)

    @router.get(f"{prefix}/")
    async def mcp_redirect():
        return RedirectResponse(prefix)

    @router.get(f"{prefix}/debug/tools")
    async def debug_tools():
        return JSONResponse({"tools": registry.get_tools_schema()})

    return router
