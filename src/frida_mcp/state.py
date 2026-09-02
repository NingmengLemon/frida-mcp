"""Thread-safe registries for frida sessions and hook scripts.

Both registries are process-wide singletons shared by the MCP tools. They
keep the frida Session/Script objects alive for as long as the MCP server
runs, buffer their messages with a cap, and clean up automatically when the
target side detaches (process exit, USB unplug, ...).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import frida

from frida_mcp._exceptions import FRIDA_ERRORS

logger = logging.getLogger(__name__)

# Cap on buffered messages per session/hook to prevent unbounded memory growth
# from chatty scripts.
MAX_MESSAGES_PER_QUEUE = 5000

# Keep the agent alive through brief USB disconnects (seconds).
PERSIST_TIMEOUT_SECONDS = 30


def new_id(prefix: str, pid: int) -> str:
    """Generate a unique, opaque ID for a session or hook."""
    return f"{prefix}_{pid}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"


@contextmanager
def _suppress_frida_errors() -> Iterator[None]:
    """Suppress expected frida errors during best-effort cleanup."""
    try:  # noqa: SIM105 - contextlib.suppress cannot take a tuple of unrelated exception types
        yield
    except FRIDA_ERRORS:
        pass


@dataclass
class SessionInfo:
    session_id: str
    session: frida.Session
    process_id: int
    device_id: str | None
    messages: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    scripts: list[frida.Script] = field(default_factory=list)
    dropped: int = 0


class SessionStore:
    """Registry of interactive sessions, keyed by session ID."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionInfo] = {}
        self._guard = threading.Lock()

    def register(self, info: SessionInfo) -> None:
        with self._guard:
            self._sessions[info.session_id] = info
        info.session.on(
            "detached",
            lambda reason, sid=info.session_id: self._on_detached(sid, reason),
        )

    def get(self, session_id: str) -> SessionInfo | None:
        with self._guard:
            info = self._sessions.get(session_id)
        if info is None:
            return None
        if self._is_detached(info):
            self._drop(session_id)
            return None
        return info

    def snapshot(self) -> list[dict[str, Any]]:
        with self._guard:
            infos = list(self._sessions.values())
        return [
            {
                "session_id": info.session_id,
                "process_id": info.process_id,
                "device_id": info.device_id,
                "scripts": len(info.scripts),
                "buffered_messages": len(info.messages),
            }
            for info in infos
            if not self._is_detached(info)
        ]

    def close(self, session_id: str) -> bool:
        """Detach the session and unload its persistent scripts. Returns False if unknown."""
        info = self._pop(session_id)
        if info is None:
            return False
        for script in info.scripts:
            self._quiet_unload(script)
        info.scripts.clear()
        self._quiet_detach(info.session)
        with info.lock:
            info.messages.clear()
        return True

    def reset(self) -> None:
        """Detach every registered session (used by tests and shutdown)."""
        with self._guard:
            infos = list(self._sessions.values())
            self._sessions.clear()
        for info in infos:
            self._quiet_detach(info.session)

    @staticmethod
    def _is_detached(info: SessionInfo) -> bool:
        try:
            return bool(info.session.is_detached)
        except FRIDA_ERRORS:
            return True

    @staticmethod
    def _quiet_detach(session: frida.Session) -> None:
        with _suppress_frida_errors():
            session.detach()

    @staticmethod
    def _quiet_unload(script: frida.Script) -> None:
        with _suppress_frida_errors():
            script.unload()

    def _pop(self, session_id: str) -> SessionInfo | None:
        with self._guard:
            return self._sessions.pop(session_id, None)

    def _drop(self, session_id: str) -> None:
        with self._guard:
            self._sessions.pop(session_id, None)

    def _on_detached(self, session_id: str, reason: str) -> None:
        if self._pop(session_id) is not None:
            logger.info("Session %s detached by target (%s)", session_id, reason)


@dataclass
class HookInfo:
    hook_id: str
    session: frida.Session
    script: frida.Script
    process_id: int
    hook_type: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    dropped: int = 0


class HookRegistry:
    """Registry of simple hooks, keyed by hook ID."""

    def __init__(self) -> None:
        self._hooks: dict[str, HookInfo] = {}
        self._guard = threading.Lock()

    def register(self, info: HookInfo) -> None:
        with self._guard:
            self._hooks[info.hook_id] = info
        info.session.on(
            "detached",
            lambda reason, hid=info.hook_id: self._on_detached(hid, reason),
        )

    def get(self, hook_id: str) -> HookInfo | None:
        with self._guard:
            return self._hooks.get(hook_id)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._guard:
            infos = list(self._hooks.values())
        return [
            {
                "hook_id": info.hook_id,
                "process_id": info.process_id,
                "hook_type": info.hook_type,
                "buffered_messages": len(info.messages),
            }
            for info in infos
        ]

    def drain_messages(self, hook_id: str) -> tuple[list[dict[str, Any]], int]:
        """Copy and clear the message queue; returns (messages, dropped_count)."""
        info = self.get(hook_id)
        if info is None:
            raise KeyError(hook_id)
        with info.lock:
            messages = list(info.messages)
            info.messages.clear()
            dropped = info.dropped
            info.dropped = 0
        return messages, dropped

    def remove(self, hook_id: str) -> bool:
        """Unload the hook script and detach its session. Returns False if unknown."""
        with self._guard:
            info = self._hooks.pop(hook_id, None)
        if info is None:
            return False
        with _suppress_frida_errors():
            info.script.unload()
        with _suppress_frida_errors():
            info.session.detach()
        return True

    def reset(self) -> None:
        """Remove every registered hook (used by tests and shutdown)."""
        with self._guard:
            infos = list(self._hooks.values())
            self._hooks.clear()
        for info in infos:
            with _suppress_frida_errors():
                info.script.unload()
            with _suppress_frida_errors():
                info.session.detach()

    def _on_detached(self, hook_id: str, reason: str) -> None:
        with self._guard:
            info = self._hooks.pop(hook_id, None)
        if info is not None:
            logger.info("Hook %s detached by target (%s)", hook_id, reason)


session_store = SessionStore()
hook_registry = HookRegistry()

__all__ = [
    "MAX_MESSAGES_PER_QUEUE",
    "PERSIST_TIMEOUT_SECONDS",
    "HookInfo",
    "HookRegistry",
    "SessionInfo",
    "SessionStore",
    "hook_registry",
    "new_id",
    "session_store",
]
