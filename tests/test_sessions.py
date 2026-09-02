"""Tests for interactive session tools (faked devices)."""

from __future__ import annotations

import frida
import pytest

from frida_mcp.state import session_store
from frida_mcp.tools import sessions
from tests.conftest import FakeDevice, FakeScript


def _receipt(result: str) -> dict:
    return {
        "type": "send",
        "payload": {
            "type": "execution_receipt",
            "result": result,
            "error": None,
            "initial_logs": [],
        },
    }


def _patch(monkeypatch, device: FakeDevice) -> None:
    monkeypatch.setattr(sessions, "resolve_device", lambda device_id: device)


def test_create_interactive_session(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    result = sessions.create_interactive_session(100)
    assert result["status"] == "success"
    session_id = result["session_id"]
    assert session_id.startswith("session_100_")
    assert session_store.get(session_id) is not None
    assert device.attached == [100]


def test_create_interactive_session_failure(monkeypatch) -> None:
    device = FakeDevice()
    device.attach_error = frida.ProcessNotFoundError("gone")
    _patch(monkeypatch, device)
    result = sessions.create_interactive_session(999)
    assert result == {"status": "error", "error": "gone"}


def test_execute_unknown_session_raises() -> None:
    with pytest.raises(ValueError):
        sessions.execute_in_session("nope", "1 + 1")


def test_execute_in_session_success(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = _receipt("42")
    _patch(monkeypatch, device)
    result = sessions.create_interactive_session(100)
    session_id = result["session_id"]
    result = sessions.execute_in_session(session_id, "40 + 2")
    assert result["status"] == "success"
    assert result["result"] == "42"
    assert result["script_unloaded"] is True
    script = device.session.scripts[-1]
    assert isinstance(script, FakeScript)
    assert script.unloaded is True
    assert "40 + 2" in script.source


def test_execute_in_session_script_error(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {"type": "error", "description": "boom"}
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    result = sessions.execute_in_session(session_id, "nope")
    assert result["status"] == "error"
    assert "boom" in result["details"]


def test_execute_in_session_timeout(monkeypatch) -> None:
    monkeypatch.setattr(sessions, "EXEC_TIMEOUT_SECONDS", 0.05)
    device = FakeDevice()
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    result = sessions.execute_in_session(session_id, "1 + 1")
    assert result["status"] == "error"
    assert "execution receipt" in result["error"]


def test_keep_alive_persists_and_collects_messages(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    result = sessions.execute_in_session(
        session_id, "setInterval(...)", keep_alive=True
    )
    assert result["status"] == "success"
    assert result["script_unloaded"] is False
    script = device.session.scripts[-1]
    assert isinstance(script, FakeScript)
    script.emit({"type": "send", "payload": {"type": "log", "message": "tick"}})
    messages = sessions.get_session_messages(session_id)
    assert messages["messages_retrieved"] == 1
    assert messages["messages"][0]["payload"]["message"] == "tick"
    assert sessions.get_session_messages(session_id)["messages_retrieved"] == 0


def test_close_session(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    assert sessions.close_session(session_id)["closed"] is True
    assert device.session.is_detached is True
    with pytest.raises(ValueError):
        sessions.close_session(session_id)
    with pytest.raises(ValueError):
        sessions.get_session_messages(session_id)


def test_session_auto_cleanup_on_detach(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    device.session.emit_detached("process-terminated")
    assert session_store.get(session_id) is None
    assert sessions.list_sessions() == []


def test_list_sessions(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    session_id = sessions.create_interactive_session(100)["session_id"]
    listing = sessions.list_sessions()
    assert listing == [
        {
            "session_id": session_id,
            "process_id": 100,
            "device_id": None,
            "scripts": 0,
            "buffered_messages": 0,
        }
    ]
