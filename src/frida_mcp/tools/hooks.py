"""Ready-made hooks (memory/file/network) with explicit lifecycle management.

Frida 17 removed the static Module.findExportByName() API, so every script here
uses Module.getGlobalExportByName() (wrapped, since it raises when the export
does not exist globally).
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastmcp import FastMCP

from frida_mcp._exceptions import FRIDA_ERRORS
from frida_mcp.devices import resolve_device
from frida_mcp.state import (
    MAX_MESSAGES_PER_QUEUE,
    PERSIST_TIMEOUT_SECONDS,
    HookInfo,
    hook_registry,
    new_id,
)
from frida_mcp.tools._fields import DeviceId, HookId, HookType, Pid

logger = logging.getLogger(__name__)

# How long to wait for the hook script to report status/error after load().
HOOK_LOAD_TIMEOUT_SECONDS = 3.0

_MEMORY_HOOK_SOURCE = """'use strict';
function hookGlobal(names, callbacks) {
  for (var i = 0; i < names.length; i++) {
    var target = null;
    try { target = Module.getGlobalExportByName(names[i]); } catch (e) { target = null; }
    if (target !== null) { Interceptor.attach(target, callbacks); return names[i]; }
  }
  return null;
}

var inLog = false;
var hooked = hookGlobal(['malloc'], {
  onEnter: function (args) {
    if (inLog) { return; }
    if (args[0].compare(ptr('0x100000')) > 0) {
      inLog = true;
      try { send({ type: 'log', message: 'malloc(' + args[0] + ' bytes)' }); } finally { inLog = false; }
    }
  }
});

if (hooked === null) {
  send({ type: 'error', message: "unable to find a global export for 'malloc'" });
} else {
  send({ type: 'status', message: 'memory hook installed on ' + hooked });
}"""

_FILE_HOOK_SOURCE = """'use strict';
function hookGlobal(names, callbacks) {
  for (var i = 0; i < names.length; i++) {
    var target = null;
    try { target = Module.getGlobalExportByName(names[i]); } catch (e) { target = null; }
    if (target !== null) { Interceptor.attach(target, callbacks); return names[i]; }
  }
  return null;
}

var hooked = hookGlobal(['open', 'open64', '_open'], {
  onEnter: function (args) {
    var path = '<unreadable>';
    try { path = args[0].readUtf8String(); } catch (e) { }
    this.path = path;
    send({ type: 'log', message: 'open(' + path + ')' });
  },
  onLeave: function (retval) {
    send({ type: 'log', message: 'open(' + this.path + ') => ' + retval });
  }
});

if (hooked === null) {
  send({ type: 'error', message: "unable to find a global export for open/open64/_open" });
} else {
  send({ type: 'status', message: 'file hook installed on ' + hooked });
}"""

_NETWORK_HOOK_SOURCE = """'use strict';
function hookGlobal(names, callbacks) {
  for (var i = 0; i < names.length; i++) {
    var target = null;
    try { target = Module.getGlobalExportByName(names[i]); } catch (e) { target = null; }
    if (target !== null) { Interceptor.attach(target, callbacks); return names[i]; }
  }
  return null;
}

var hooked = hookGlobal(['connect'], {
  onEnter: function () {
    send({ type: 'log', message: 'connect() called' });
  },
  onLeave: function (retval) {
    send({ type: 'log', message: 'connect() => ' + retval });
  }
});

if (hooked === null) {
  send({ type: 'error', message: "unable to find a global export for 'connect'" });
} else {
  send({ type: 'status', message: 'network hook installed on ' + hooked });
}"""

_HOOK_SOURCES: dict[str, str] = {
    "memory": _MEMORY_HOOK_SOURCE,
    "file": _FILE_HOOK_SOURCE,
    "network": _NETWORK_HOOK_SOURCE,
}


def create_simple_hook(
    pid: Pid,
    hook_type: HookType = "memory",
    device_id: DeviceId = None,
) -> dict[str, Any]:
    """Attach to a process and install a ready-made hook (memory/file/network).

    Returns a hook_id on success. Hook output (send() calls) is buffered per
    hook and retrieved with get_hook_messages; console.log goes to the
    target's own stdout. Tear the hook down with remove_hook. The hook
    reports an error (success False) when the target export does not exist
    on that platform.
    """
    source = _HOOK_SOURCES.get(hook_type)
    if source is None:
        known = ", ".join(sorted(_HOOK_SOURCES))
        return {
            "success": False,
            "error": f"Unknown hook type: {hook_type!r}. Use one of: {known}",
        }

    try:
        session = resolve_device(device_id).attach(
            pid, persist_timeout=PERSIST_TIMEOUT_SECONDS
        )
    except FRIDA_ERRORS as exc:
        return {"success": False, "error": str(exc)}

    hook_id = new_id("hook", pid)
    script = session.create_script(source)
    info = HookInfo(
        hook_id=hook_id,
        session=session,
        script=script,
        process_id=pid,
        hook_type=hook_type,
    )
    ready = threading.Event()

    def on_message(message: Any, data: Any) -> None:
        with info.lock:
            if len(info.messages) < MAX_MESSAGES_PER_QUEUE:
                info.messages.append(
                    {
                        "type": message.get("type"),
                        "payload": message.get("payload"),
                        "description": message.get("description"),
                        "data": data,
                    }
                )
            else:
                info.dropped += 1
        if message.get("type") in ("send", "error"):
            ready.set()

    script.on("message", on_message)
    try:
        script.load()
    except FRIDA_ERRORS as exc:
        session.detach()
        return {"success": False, "error": str(exc)}

    hook_registry.register(info)

    if not ready.wait(timeout=HOOK_LOAD_TIMEOUT_SECONDS):
        return {
            "success": False,
            "hook_id": hook_id,
            "process_id": pid,
            "hook_type": hook_type,
            "error": (
                "Hook script did not report status within "
                f"{HOOK_LOAD_TIMEOUT_SECONDS}s; the hook stays installed, "
                "call remove_hook to clean it up."
            ),
            "messages": list(info.messages),
        }

    errors = []
    for message in info.messages:
        payload = message.get("payload") or {}
        is_error = message.get("type") == "error" or payload.get("type") == "error"
        if not is_error:
            continue
        errors.append(payload.get("message") or message.get("description"))
    if errors:
        return {
            "success": False,
            "hook_id": hook_id,
            "process_id": pid,
            "hook_type": hook_type,
            "error": errors[0],
            "messages": list(info.messages),
        }
    return {
        "success": True,
        "hook_id": hook_id,
        "process_id": pid,
        "hook_type": hook_type,
        "messages": list(info.messages),
    }


def list_hooks() -> list[dict[str, Any]]:
    """List all active hooks."""
    return hook_registry.snapshot()


def get_hook_messages(hook_id: HookId) -> dict[str, Any]:
    """Retrieve and clear messages captured by a hook."""
    try:
        messages, dropped = hook_registry.drain_messages(hook_id)
    except KeyError:
        raise ValueError(f"Hook with ID {hook_id} not found") from None
    return {
        "success": True,
        "hook_id": hook_id,
        "messages_retrieved": len(messages),
        "dropped": dropped,
        "messages": messages,
    }


def remove_hook(hook_id: HookId) -> dict[str, Any]:
    """Unload a hook script and detach its session."""
    if not hook_registry.remove(hook_id):
        raise ValueError(f"Hook with ID {hook_id} not found")
    return {"success": True, "hook_id": hook_id}


def register(mcp: FastMCP) -> None:
    for fn in (create_simple_hook, list_hooks, get_hook_messages, remove_hook):
        mcp.add_tool(fn)
