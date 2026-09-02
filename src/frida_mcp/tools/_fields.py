"""Shared Annotated parameter types for MCP tools.

FastMCP builds the JSON schema from pydantic Field metadata carried by
Annotated[...]; keeping the real Python defaults (None, False, ...) on the
signature means the tools are safe to call directly, not only through the
MCP protocol (where defaults are resolved by the generated pydantic model).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

DeviceId = Annotated[
    str | None,
    Field(
        default=None,
        description="Optional device ID. When omitted, the default device is used: USB first, local fallback.",
    ),
]

Pid = Annotated[int, Field(description="The ID of the target process.")]

SessionId = Annotated[
    str, Field(description="The unique identifier of an active Frida session.")
]

HookId = Annotated[str, Field(description="The unique identifier of an active hook.")]

Args = Annotated[
    list[str] | None,
    Field(default=None, description="Optional list of arguments for the program."),
]

HookType = Annotated[
    str,
    Field(
        default="memory",
        description="Hook kind: memory (large malloc calls), file (open calls), or network (connect calls).",
    ),
]

KeepAlive = Annotated[
    bool,
    Field(
        default=False,
        description="If True the script stays loaded for hooks/RPC and its messages are collected via get_session_messages. If False (default) it is unloaded after the initial execution.",
    ),
]

__all__ = ["Args", "DeviceId", "HookId", "HookType", "KeepAlive", "Pid", "SessionId"]
