"""MCP tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from frida_mcp.tools import device_tools, hooks, processes, sessions


def register_tools(mcp: FastMCP) -> None:
    """Register every MCP tool on the given server instance."""
    device_tools.register(mcp)
    processes.register(mcp)
    hooks.register(mcp)
    sessions.register(mcp)


__all__ = ["register_tools"]
