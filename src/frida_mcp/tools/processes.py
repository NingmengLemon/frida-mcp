"""Process-related MCP tools."""

from __future__ import annotations

from typing import Any, cast

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from frida_mcp._exceptions import FRIDA_ERRORS
from frida_mcp.devices import resolve_device
from frida_mcp.tools._fields import Args, DeviceId, Pid


def _list_processes(device_id: str | None) -> list[dict[str, Any]]:
    device = resolve_device(device_id)
    return [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]


def list_processes() -> list[dict[str, Any]]:
    """List all processes running on the default device."""
    return _list_processes(None)


def enumerate_processes(device_id: DeviceId = None) -> list[dict[str, Any]]:
    """List all processes running on a device."""
    return _list_processes(device_id)


def get_process_by_name(
    name: str = Field(
        description="The name (or part of the name) of the process to find. Case-insensitive."
    ),
    device_id: DeviceId = None,
) -> dict[str, Any]:
    """Find a process by name (case-insensitive substring match)."""
    for proc in resolve_device(device_id).enumerate_processes():
        if name.lower() in proc.name.lower():
            return {"pid": proc.pid, "name": proc.name, "found": True}
    return {"found": False, "error": f"Process {name!r} not found"}


def attach_to_process(pid: Pid, device_id: DeviceId = None) -> dict[str, Any]:
    """Attach to a process to verify attachability, then detach immediately.

    For persistent instrumentation use create_interactive_session (REPL-style)
    or create_simple_hook (ready-made hooks); both keep their session alive.
    """
    try:
        session = resolve_device(device_id).attach(pid)
        session.detach()
        return {"pid": pid, "success": True, "is_detached": True}
    except FRIDA_ERRORS as exc:
        return {"success": False, "error": str(exc)}


def spawn_process(
    program: str = Field(description="The program or application identifier to spawn."),
    args: Args = None,
    device_id: DeviceId = None,
) -> dict[str, Any]:
    """Spawn a program on a device (stays suspended until resume_process)."""
    try:
        pid = resolve_device(device_id).spawn(
            program, argv=cast(list[str | bytes] | None, args)
        )
    except FRIDA_ERRORS as exc:
        return {"success": False, "error": f"Failed to spawn {program}: {exc}"}
    return {"success": True, "pid": pid}


def resume_process(pid: Pid, device_id: DeviceId = None) -> dict[str, Any]:
    """Resume a suspended process by ID."""
    try:
        resolve_device(device_id).resume(pid)
    except FRIDA_ERRORS as exc:
        return {"success": False, "error": f"Failed to resume process {pid}: {exc}"}
    return {"success": True, "pid": pid}


def kill_process(pid: Pid, device_id: DeviceId = None) -> dict[str, Any]:
    """Kill a process by ID."""
    try:
        resolve_device(device_id).kill(pid)
    except FRIDA_ERRORS as exc:
        return {"success": False, "error": f"Failed to kill process {pid}: {exc}"}
    return {"success": True, "pid": pid}


def register(mcp: FastMCP) -> None:
    mcp.tool()(list_processes)
    mcp.tool()(enumerate_processes)
    mcp.tool()(get_process_by_name)
    mcp.tool()(attach_to_process)
    mcp.tool()(spawn_process)
    mcp.tool()(resume_process)
    mcp.tool()(kill_process)
