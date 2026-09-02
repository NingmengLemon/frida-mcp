"""Device-related MCP tools, including remote frida-server connections."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any

import frida
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from frida_mcp._exceptions import FRIDA_ERRORS

Port = Annotated[
    int,
    Field(
        default=27042, description="Port of the remote frida-server. Defaults to 27042."
    ),
]
OptCert = Annotated[
    str | None,
    Field(default=None, description="Optional TLS certificate for the connection."),
]
OptOrigin = Annotated[
    str | None,
    Field(default=None, description="Optional origin header for the connection."),
]
OptToken = Annotated[
    str | None,
    Field(
        default=None, description="Optional authentication token for the remote device."
    ),
]
OptKeepalive = Annotated[
    int | None,
    Field(default=None, description="Optional keepalive interval in seconds."),
]


def _device_info(device: frida.Device) -> dict[str, Any]:
    return {"id": device.id, "name": device.name, "type": device.type}


def _format_address(host: str, port: int) -> str:
    """Format a host:port address, bracketing IPv6 addresses correctly."""
    bare = host.strip("[]")
    try:
        if isinstance(ipaddress.ip_address(bare), ipaddress.IPv6Address):
            return f"[{bare}]:{port}"
    except ValueError:
        pass
    return f"{bare}:{port}"


def enumerate_devices() -> list[dict[str, Any]]:
    """List all devices connected to the system (USB, local, and remote)."""
    return [_device_info(d) for d in frida.enumerate_devices()]


def get_device(
    device_id: str = Field(description="The ID of the device to get"),
) -> dict[str, Any]:
    """Get a device by its ID."""
    try:
        return _device_info(frida.get_device(device_id))
    except frida.InvalidArgumentError:
        raise ValueError(f"Device with ID {device_id} not found") from None


def get_usb_device() -> dict[str, Any]:
    """Get the USB device connected to the system."""
    try:
        return _device_info(frida.get_usb_device())
    except frida.InvalidArgumentError:
        raise ValueError("No USB device found") from None


def get_local_device() -> dict[str, Any]:
    """Get the local device."""
    try:
        return _device_info(frida.get_local_device())
    except frida.InvalidArgumentError:
        raise ValueError("No local device found or error accessing it.") from None


def add_remote_device(
    host: str = Field(
        description="Hostname or IP address of the remote frida-server (e.g. 192.168.1.100 or myhost)."
    ),
    port: Port = 27042,
    certificate: OptCert = None,
    origin: OptOrigin = None,
    token: OptToken = None,
    keepalive_interval: OptKeepalive = None,
) -> dict[str, Any]:
    """Connect to a remote frida-server by hostname and port.

    Once added, the device appears in enumerate_devices() and can be referenced
    by its device_id in every other tool.
    """
    address = _format_address(host, port)
    kwargs: dict[str, Any] = {}
    if certificate is not None:
        kwargs["certificate"] = certificate
    if origin is not None:
        kwargs["origin"] = origin
    if token is not None:
        kwargs["token"] = token
    if keepalive_interval is not None:
        kwargs["keepalive_interval"] = keepalive_interval
    try:
        device = frida.get_device_manager().add_remote_device(address, **kwargs)
    except FRIDA_ERRORS as exc:
        raise ValueError(f"Failed to add remote device at {address}: {exc}") from exc
    info = _device_info(device)
    info["address"] = address
    return info


def remove_remote_device(
    host: str = Field(
        description="Hostname or IP address of the remote frida-server to disconnect."
    ),
    port: Port = 27042,
) -> dict[str, Any]:
    """Disconnect from a previously added remote frida-server."""
    address = _format_address(host, port)
    try:
        frida.get_device_manager().remove_remote_device(address)
    except FRIDA_ERRORS as exc:
        raise ValueError(f"Failed to remove remote device at {address}: {exc}") from exc
    return {"success": True, "address": address}


def register(mcp: FastMCP) -> None:
    mcp.tool()(enumerate_devices)
    mcp.tool()(get_device)
    mcp.tool()(get_usb_device)
    mcp.tool()(get_local_device)
    mcp.tool()(add_remote_device)
    mcp.tool()(remove_remote_device)
