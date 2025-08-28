"""
Copyright 2025 Grabtaxi Holdings Pte Ltd (GRAB), All rights reserved.
Use of this source code is governed by an MIT-style license that can be found in the LICENSE file
"""

import inspect
import json
from typing import Any, Callable, Dict, List, Optional
from functools import wraps


class ToolRegistry:
    """Registry for MCP tools with automatic serialization."""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._custom_serializer: Optional[Callable[[Any], Any]] = None

    def tool(self, name: Optional[str] = None, description: Optional[str] = None):
        """Decorator to register a function as an MCP tool."""

        def decorator(func: Callable) -> Callable:
            tool_name = name or func.__name__
            tool_description = description or func.__doc__ or f"Execute {tool_name}"

            @wraps(func)
            async def wrapper(**kwargs):
                # Call function (async or sync)
                result = (
                    await func(**kwargs)
                    if inspect.iscoroutinefunction(func)
                    else func(**kwargs)
                )
                # Auto-serialize result
                return self._serialize(result)

            # Register tool with schema
            self._tools[tool_name] = {
                "name": tool_name,
                "description": tool_description.strip(),
                "function": wrapper,
                "schema": self._build_schema(func),
            }

            return wrapper

        return decorator

    def _serialize(self, result: Any) -> Any:
        """Auto-serialize result to JSON-safe format."""
        try:
            json.dumps(result)  # Test if already serializable
            return result
        except (TypeError, ValueError):
            # Try custom serializer if available
            if self._custom_serializer:
                try:
                    return self._custom_serializer(result)
                except Exception:
                    pass

            # Try built-in serialization for common cases
            try:
                return self._default_serialize(result)
            except Exception:
                # Final fallback to string representation
                return {"data": str(result), "type": type(result).__name__}

    def _default_serialize(self, result: Any) -> Any:
        """Built-in serialization for common object types."""
        # Handle SQLAlchemy models
        if hasattr(result, "__table__"):  # SQLAlchemy model
            return self._serialize_sqlalchemy_model(result)

        # Handle lists/tuples of objects
        if isinstance(result, (list, tuple)):
            return [self._serialize(item) for item in result]

        # Handle dictionaries
        if isinstance(result, dict):
            return {key: self._serialize(value) for key, value in result.items()}

        # Handle objects with __dict__
        if hasattr(result, "__dict__"):
            return {
                key: self._serialize(value)
                for key, value in result.__dict__.items()
                if not key.startswith("_")
            }

        # Can't serialize, let it raise
        raise TypeError(f"Cannot serialize {type(result)}")

    def _serialize_sqlalchemy_model(self, model) -> Dict[str, Any]:
        """Serialize SQLAlchemy model to dictionary."""
        try:
            # Get all column names from the table
            columns = [column.name for column in model.__table__.columns]
            return {column: getattr(model, column) for column in columns}
        except Exception:
            # Fallback to basic __dict__ approach
            return {
                key: value
                for key, value in model.__dict__.items()
                if not key.startswith("_")
            }

    def set_custom_serializer(self, serializer: Callable[[Any], Any]):
        """Set a custom serializer function for complex objects."""
        self._custom_serializer = serializer

    def _build_schema(self, func: Callable) -> Dict[str, Any]:
        """Build JSON schema from function signature."""
        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            # Map Python types to JSON schema types
            param_type = "string"  # Default
            if (
                hasattr(param, "annotation")
                and param.annotation != inspect.Parameter.empty
            ):
                type_map = {
                    str: "string",
                    int: "integer",
                    float: "number",
                    bool: "boolean",
                }
                param_type = type_map.get(param.annotation, "string")

            properties[param_name] = {"type": param_type}

            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {"type": "object", "properties": properties, "required": required}

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Get all tools in MCP format."""
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": tool["schema"],
                "parameters": tool["schema"],  # MCP compatibility
            }
            for tool in self._tools.values()
        ]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool by name."""
        if name not in self._tools:
            raise ValueError(f"Tool '{name}' not found")
        return await self._tools[name]["function"](**arguments)

    def get_tool_names(self) -> List[str]:
        """Get list of registered tool names."""
        return list(self._tools.keys())


# Global registry for convenience
_default_registry = ToolRegistry()


def mcp_tool(name: Optional[str] = None, description: Optional[str] = None):
    """Register a function as an MCP tool using the default registry."""
    return _default_registry.tool(name, description)


def get_default_registry() -> ToolRegistry:
    """Get the default global tool registry."""
    return _default_registry
