"""Frida MCP: a Model Context Protocol server for the Frida dynamic instrumentation toolkit.

Create a fully wired server with::

    from frida_mcp.server import create_server
    mcp = create_server()
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("frida-mcp")
except (
    PackageNotFoundError
):  # pragma: no cover - source checkout without installed metadata
    __version__ = "0.0.0"

__all__ = ["__version__"]
