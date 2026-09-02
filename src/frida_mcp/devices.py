"""Device selection policy: USB first, local fallback."""

from __future__ import annotations

import logging

import frida

from frida_mcp._exceptions import FRIDA_ERRORS

logger = logging.getLogger(__name__)

__all__ = ["default_device", "resolve_device"]


def default_device() -> frida.Device:
    """Return the USB device when present, otherwise the local device.

    This matches the common workflow of instrumenting a real Android/iOS device
    over USB while still working on desktop targets when no USB device exists.

    A warning is logged when the fallback happens so that a broken USB setup
    (wrong frida-server version, adb offline, ...) does not silently redirect
    tool calls to the local machine.
    """
    try:
        return frida.get_usb_device()
    except FRIDA_ERRORS as exc:
        logger.warning("USB device unavailable (%s); falling back to local device", exc)
        return frida.get_local_device()


def resolve_device(device_id: str | None) -> frida.Device:
    """Resolve an explicit device ID, or the default device when None."""
    if device_id:
        return frida.get_device(device_id)
    return default_device()
