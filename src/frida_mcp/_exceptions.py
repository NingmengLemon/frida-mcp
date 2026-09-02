"""Shared frida exception types for narrow, intentional error handling.

frida 17.x exposes no common base class for its exceptions (each derives directly
from Exception), so we enumerate them here. Tools catch this tuple instead of a
blind "except Exception", keeping unexpected bugs visible.
"""

from __future__ import annotations

import frida

FRIDA_ERRORS: tuple[type[BaseException], ...] = (
    frida.AddressInUseError,
    frida.ExecutableNotFoundError,
    frida.ExecutableNotSupportedError,
    frida.InvalidArgumentError,
    frida.InvalidOperationError,
    frida.NotSupportedError,
    frida.OperationCancelledError,
    frida.PermissionDeniedError,
    frida.ProcessNotFoundError,
    frida.ProcessNotRespondingError,
    frida.ProtocolError,
    frida.ServerNotRunningError,
    frida.TimedOutError,
    frida.TransportError,
)

__all__ = ["FRIDA_ERRORS"]
