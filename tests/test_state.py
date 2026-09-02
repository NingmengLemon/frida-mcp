"""Tests for the session store and hook registry."""

from __future__ import annotations

from frida_mcp.state import HookInfo, SessionInfo, SessionStore
from tests.conftest import FakeScript, FakeSession


def _session_info(session_id: str = "s1") -> SessionInfo:
    return SessionInfo(
        session_id=session_id,
        session=FakeSession(),  # type: ignore[arg-type]
        process_id=100,
        device_id=None,
    )


def test_register_get_list() -> None:
    store = SessionStore()
    info = _session_info()
    store.register(info)
    assert store.get("s1") is info
    listing = store.snapshot()
    assert listing == [
        {
            "session_id": "s1",
            "process_id": 100,
            "device_id": None,
            "scripts": 0,
            "buffered_messages": 0,
        }
    ]


def test_close_detaches_and_unloads() -> None:
    store = SessionStore()
    info = _session_info()
    session = info.session
    assert isinstance(session, FakeSession)
    script = FakeScript("send({})")
    info.scripts.append(script)  # type: ignore[arg-type]
    store.register(info)
    assert store.close("s1") is True
    assert session.is_detached is True
    assert script.unloaded is True
    assert store.close("s1") is False


def test_detached_signal_removes_session() -> None:
    store = SessionStore()
    info = _session_info()
    store.register(info)
    session = info.session
    assert isinstance(session, FakeSession)
    session.emit_detached("process-terminated")
    assert store.get("s1") is None


def test_get_drops_detached_session() -> None:
    store = SessionStore()
    info = _session_info()
    store.register(info)
    session = info.session
    assert isinstance(session, FakeSession)
    session.is_detached = True
    assert store.get("s1") is None


def test_hook_registry_remove_unloads_and_detaches() -> None:
    from frida_mcp.state import HookRegistry

    registry = HookRegistry()
    session = FakeSession()
    script = FakeScript("send({})")
    info = HookInfo(
        hook_id="h1",
        session=session,  # type: ignore[arg-type]
        script=script,  # type: ignore[arg-type]
        process_id=100,
        hook_type="memory",
    )
    registry.register(info)
    assert registry.get("h1") is info
    assert registry.remove("h1") is True
    assert script.unloaded is True
    assert session.is_detached is True
    assert registry.remove("h1") is False
