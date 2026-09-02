"""FastMCP server factory."""

from __future__ import annotations

from fastmcp import FastMCP

from frida_mcp import resources
from frida_mcp.tools import register_tools


def create_server(name: str = "Frida") -> FastMCP:
    """Create a fully wired Frida MCP server (tools + resources + prompts)."""
    mcp = FastMCP(name)
    register_tools(mcp)
    resources.register(mcp)
    return mcp


__all__ = ["create_server"]
