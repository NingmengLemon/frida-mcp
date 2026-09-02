"""Command line entry point for MCP clients (Claude Desktop, ...) over STDIO."""

from frida_mcp.server import create_server


def main() -> None:
    """Run the Frida MCP server on the STDIO transport."""
    create_server().run()


if __name__ == "__main__":
    main()
