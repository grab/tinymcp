"""Pytest configuration for TinyMCP tests."""

import pytest
from tinymcp import get_default_registry


@pytest.fixture(autouse=True)
def clean_registry():
    """Clean the default registry before each test to avoid test interference."""
    registry = get_default_registry()
    original_tools = registry._tools.copy()
    yield
    registry._tools = original_tools
