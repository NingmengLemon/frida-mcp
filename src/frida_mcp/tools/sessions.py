"""Interactive session tools: REPL-style script execution against attached processes."""

from __future__ import annotations

import threading
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from frida_mcp._exceptions import FRIDA_ERRORS
from frida_mcp.devices import resolve_device
from frida_mcp.state import (
    MAX_MESSAGES_PER_QUEUE,
    PERSIST_TIMEOUT_SECONDS,
    SessionInfo,
    new_id,
    session_store,
)
from frida_mcp.tools._fields import DeviceId, KeepAlive, SessionId

# How long to wait for the initial execution receipt of a non-persistent script.
EXEC_TIMEOUT_SECONDS = 3.0


def create_interactive_session(
    process_id: int = Field(
        description="The ID of the process to attach to for creating an interactive session."
    ),
    device_id: DeviceId = None,
) -> dict[str, Any]:
    """Create an interactive REPL-like session with a process.

    Returns a session ID for execute_in_session and get_session_messages.
    The session survives brief USB disconnects (persist_timeout).
    """
    try:
        session = resolve_device(device_id).attach(
            process_id, persist_timeout=PERSIST_TIMEOUT_SECONDS
        )
    except FRIDA_ERRORS as exc:
        return {"status": "error", "error": str(exc)}

    session_id = new_id("session", process_id)
    session_store.register(
        SessionInfo(
            session_id=session_id,
            session=session,
            process_id=process_id,
            device_id=device_id,
        )
    )
    return {
        "status": "success",
        "process_id": process_id,
        "session_id": session_id,
        "message": (
            f"Interactive session created for process {process_id}. "
            "Use execute_in_session to run JavaScript commands."
        ),
    }


def execute_in_session(
    session_id: SessionId,
    javascript_code: str = Field(
        description="JavaScript to execute in the target process. May use the Frida JS API (Interceptor, Memory, Module, rpc, ...).",
    ),
    keep_alive: KeepAlive = False,
) -> dict[str, Any]:
    """Execute JavaScript code within an existing interactive Frida session."""
    info = session_store.get(session_id)
    if info is None:
        raise ValueError(f"Session with ID {session_id} not found")
    session = info.session
    lock = info.lock

    # Wrap the code to capture console.log output and the completion result.
    wrapped_code = f"""
(function() {{
    var initialLogs = [];
    var originalLog = console.log;

    console.log = function() {{
        var args = Array.prototype.slice.call(arguments);
        var logMsg = args.map(function(arg) {{
            return typeof arg === "object" ? JSON.stringify(arg) : String(arg);
        }}).join(" ");
        initialLogs.push(logMsg);
        originalLog.apply(console, arguments);
    }};

    var scriptResult;
    var scriptError;
    try {{
        scriptResult = eval({javascript_code!r});
    }} catch (e) {{
        scriptError = {{ message: e.toString(), stack: e.stack }};
    }}

    console.log = originalLog;

    send({{
        type: "execution_receipt",
        result: scriptError ? undefined : (scriptResult !== undefined ? scriptResult.toString() : "undefined"),
        error: scriptError,
        initial_logs: initialLogs
    }});
}})();
"""

    script = session.create_script(wrapped_code)
    receipt_event = threading.Event()
    initial_results: list[dict[str, Any]] = []

    def on_initial_message(message: Any, data: Any) -> None:
        if (
            message.get("type") == "send"
            and (message.get("payload") or {}).get("type") == "execution_receipt"
        ):
            initial_results.append(message["payload"])
            receipt_event.set()
        elif message.get("type") == "error":
            initial_results.append(
                {"script_error": message.get("description"), "details": message}
            )
            receipt_event.set()

    def on_persistent_message(message: Any, data: Any) -> None:
        with lock:
            if len(info.messages) < MAX_MESSAGES_PER_QUEUE:
                info.messages.append(
                    {
                        "type": message.get("type"),
                        "payload": message.get("payload"),
                        "data": data,
                    }
                )
            else:
                info.dropped += 1

    if keep_alive:
        script.on("message", on_persistent_message)
        info.scripts.append(script)
    else:
        script.on("message", on_initial_message)

    try:
        script.load()
        if not keep_alive and not receipt_event.wait(EXEC_TIMEOUT_SECONDS):
            script.unload()
            return {
                "status": "error",
                "error": (
                    "Script did not send an execution receipt within "
                    f"{EXEC_TIMEOUT_SECONDS}s"
                ),
            }
    except FRIDA_ERRORS as exc:
        return {
            "status": "error",
            "error": f"Frida operation error: {exc} (Session may be detached)",
        }

    final_result: dict[str, Any]
    if initial_results:
        receipt = initial_results[0]
        if "script_error" in receipt:
            final_result = {
                "status": "error",
                "error": "Script execution error",
                "details": receipt["script_error"],
            }
        elif receipt.get("error"):
            final_result = {
                "status": "error",
                "error": receipt["error"]["message"],
                "stack": receipt["error"]["stack"],
                "initial_logs": receipt.get("initial_logs", []),
            }
        else:
            final_result = {
                "status": "success",
                "result": receipt["result"],
                "initial_logs": receipt.get("initial_logs", []),
            }
    elif keep_alive:
        final_result = {
            "status": "success",
            "message": (
                "Script loaded persistently. Use get_session_messages to retrieve "
                "asynchronous messages."
            ),
            "initial_logs": [],
        }
    else:
        final_result = {
            "status": "nodata",
            "message": "Script loaded but sent no initial messages.",
            "initial_logs": [],
        }

    if keep_alive:
        final_result["script_unloaded"] = False
        final_result["info"] = (
            "Script is persistent; close_session unloads it and detaches."
        )
    else:
        script.unload()
        final_result["script_unloaded"] = True
    return final_result


def get_session_messages(session_id: SessionId) -> dict[str, Any]:
    """Retrieve and clear messages sent by persistent scripts in a session."""
    info = session_store.get(session_id)
    if info is None:
        raise ValueError(f"Session with ID {session_id} not found")
    with info.lock:
        messages = list(info.messages)
        info.messages.clear()
        dropped = info.dropped
        info.dropped = 0
    return {
        "status": "success",
        "session_id": session_id,
        "messages_retrieved": len(messages),
        "dropped": dropped,
        "messages": messages,
    }


def list_sessions() -> list[dict[str, Any]]:
    """List all interactive sessions."""
    return session_store.snapshot()


def close_session(session_id: SessionId) -> dict[str, Any]:
    """Detach an interactive session and unload its persistent scripts."""
    if not session_store.close(session_id):
        raise ValueError(f"Session with ID {session_id} not found")
    return {"status": "success", "session_id": session_id, "closed": True}


def register(mcp: FastMCP) -> None:
    mcp.tool()(create_interactive_session)
    mcp.tool()(execute_in_session)
    mcp.tool()(get_session_messages)
    mcp.tool()(list_sessions)
    mcp.tool()(close_session)
