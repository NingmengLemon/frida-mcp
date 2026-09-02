"""MCP prompts for guided Frida analysis workflows."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP


def analyze_app_prompt(app_name: str) -> str:
    """Create a prompt to help analyze an application."""
    return f"""I want to analyze the {app_name} application using Frida.
Please help me create a strategy to:

1. Find the process
2. Identify key functions to hook
3. Monitor sensitive operations
4. Detect security vulnerabilities

What approach would you recommend for analyzing {app_name}?"""


def inject_script_prompt(process_id: int) -> str:
    """Create a prompt to help inject a script into a process."""
    return f"""I want to inject a Frida script into process {process_id}.
Please help me write a script to:
1. Hook common functions
2. Log interesting information
3. Manipulate program behavior if needed

What Frida script would you recommend?"""


def analyze_process_prompt(process_id: int) -> str:
    """Create a prompt to analyze a process."""
    return f"""I want to analyze process {process_id} using Frida.
Please guide me through:
1. Attaching to the process
2. Identifying interesting functions to hook
3. Finding important data structures
4. Creating effective instrumentation

What approach would you recommend?"""


def register(mcp: FastMCP) -> None:
    mcp.prompt()(analyze_app_prompt)
    mcp.prompt()(inject_script_prompt)
    mcp.prompt()(analyze_process_prompt)
