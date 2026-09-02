"""Shared fakes for unit tests; no real frida device is required."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from frida_mcp.state import hook_registry, session_store


class FakeProcess:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.name = name


class FakeScript:
    def __init__(self, source: str) -> None:
        self.source = source
        self.loaded = False
        self.unloaded = False
        self.auto_emit: dict[str, Any] | None = None
        self._handlers: list[Callable[..., None]] = []

    def on(self, signal: str, callback: Callable[..., None]) -> None:
        assert signal == "message"
        self._handlers.append(callback)

    def load(self) -> None:
        self.loaded = True
        if self.auto_emit is not None:
            self.emit(self.auto_emit)

    def unload(self) -> None:
        self.unloaded = True

    def emit(self, message: dict[str, Any], data: bytes | None = None) -> None:
        for handler in self._handlers:
            handler(message, data)


class FakeSession:
    def __init__(self) -> None:
        self.is_detached = False
        self.scripts: list[FakeScript] = []
        self.auto_emit: dict[str, Any] | None = None
        self._detached_handlers: list[Callable[[str], None]] = []

    def on(self, signal: str, callback: Callable[..., None]) -> None:
        if signal == "detached":
            self._detached_handlers.append(callback)

    def detach(self) -> None:
        self.is_detached = True
        for handler in list(self._detached_handlers):
            handler("detached")

    def create_script(self, source: str) -> FakeScript:
        script = FakeScript(source)
        if self.auto_emit is not None:
            script.auto_emit = self.auto_emit
        self.scripts.append(script)
        return script

    def emit_detached(self, reason: str = "process-terminated") -> None:
        for handler in list(self._detached_handlers):
            handler(reason)


class FakeDevice:
    def __init__(self, processes: list[FakeProcess] | None = None) -> None:
        self.id = "local"
        self.name = "Local System"
        self.type = "local"
        self.processes = processes or []
        self.attached: list[int] = []
        self.killed: list[int] = []
        self.resumed: list[int] = []
        self.spawned: list[tuple[str, list[str] | None]] = []
        self.attach_error: Exception | None = None
        self.spawn_error: Exception | None = None
        self.resume_error: Exception | None = None
        self.kill_error: Exception | None = None
        self.session = FakeSession()

    def enumerate_processes(self) -> list[FakeProcess]:
        return list(self.processes)

    def attach(self, pid: int, **kwargs: Any) -> FakeSession:
        if self.attach_error is not None:
            raise self.attach_error
        self.attached.append(pid)
        return self.session

    def spawn(self, program: str, **kwargs: Any) -> int:
        if self.spawn_error is not None:
            raise self.spawn_error
        self.spawned.append((program, kwargs.get("argv")))
        return 4242

    def resume(self, pid: int) -> None:
        if self.resume_error is not None:
            raise self.resume_error
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        if self.kill_error is not None:
            raise self.kill_error
        self.killed.append(pid)


@pytest.fixture(autouse=True)
def _clean_state() -> None:
    session_store.reset()
    hook_registry.reset()
    yield
    session_store.reset()
    hook_registry.reset()
