"""FastMCP server factory."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from frida_mcp import prompts, resources
from frida_mcp.tools import register_tools


def create_server(name: str = "Frida") -> FastMCP:
    """Create a fully wired Frida MCP server (tools + resources + prompts)."""
    mcp = FastMCP(name)
    register_tools(mcp)
    resources.register(mcp)
    prompts.register(mcp)
    return mcp


__all__ = ["create_server"]
