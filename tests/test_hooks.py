"""Tests for ready-made hook tools (faked devices)."""

from __future__ import annotations

import frida
import pytest

from frida_mcp.state import hook_registry
from frida_mcp.tools import hooks
from tests.conftest import FakeDevice


def _patch(monkeypatch, device: FakeDevice) -> None:
    monkeypatch.setattr(hooks, "resolve_device", lambda device_id: device)


def test_unknown_hook_type(monkeypatch) -> None:
    device = FakeDevice()
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100, hook_type="bogus")
    assert result["success"] is False
    assert "Unknown hook type" in result["error"]
    assert device.attached == []


def test_memory_hook_success(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {
        "type": "send",
        "payload": {"type": "status", "message": "memory hook installed on malloc"},
    }
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100, hook_type="memory")
    assert result["success"] is True
    assert result["process_id"] == 100
    assert result["hook_type"] == "memory"
    hook_id = result["hook_id"]
    info = hook_registry.get(hook_id)
    assert info is not None
    source = info.script.source
    # frida 17 API compatibility
    assert "Module.getGlobalExportByName" in source
    assert "Module.findExportByName" not in source


def test_memory_hook_reports_script_error(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {
        "type": "error",
        "description": "TypeError: not a function",
        "stack": "at /script1.js:3",
    }
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100)
    assert result["success"] is False
    assert "TypeError" in result["error"]
    assert hook_registry.get(result["hook_id"]) is not None


def test_memory_hook_reports_missing_export(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {
        "type": "send",
        "payload": {
            "type": "error",
            "message": "unable to find a global export for malloc",
        },
    }
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100)
    assert result["success"] is False
    assert "unable to find a global export" in result["error"]


def test_hook_attach_failure(monkeypatch) -> None:
    device = FakeDevice()
    device.attach_error = frida.ProcessNotFoundError("gone")
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(999)
    assert result == {"success": False, "error": "gone"}


def test_hook_load_timeout(monkeypatch) -> None:
    monkeypatch.setattr(hooks, "HOOK_LOAD_TIMEOUT_SECONDS", 0.05)
    device = FakeDevice()
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100)
    assert result["success"] is False
    assert "did not report status" in result["error"]
    assert hook_registry.get(result["hook_id"]) is not None


def test_hook_message_roundtrip_and_removal(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {
        "type": "send",
        "payload": {"type": "status", "message": "memory hook installed on malloc"},
    }
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100)
    hook_id = result["hook_id"]
    info = hook_registry.get(hook_id)
    assert info is not None
    script = info.script
    from tests.conftest import FakeScript

    assert isinstance(script, FakeScript)
    # First drain: the initial status message.
    assert hooks.get_hook_messages(hook_id)["messages_retrieved"] == 1
    script.emit(
        {"type": "send", "payload": {"type": "log", "message": "malloc(2097152 bytes)"}}
    )
    messages = hooks.get_hook_messages(hook_id)
    assert messages["messages_retrieved"] == 1
    assert "2097152" in messages["messages"][0]["payload"]["message"]
    assert hooks.get_hook_messages(hook_id)["messages_retrieved"] == 0
    assert hooks.remove_hook(hook_id)["success"] is True
    assert hook_registry.get(hook_id) is None
    assert script.unloaded is True
    assert device.session.is_detached is True
    with pytest.raises(ValueError):
        hooks.remove_hook(hook_id)


def test_list_hooks(monkeypatch) -> None:
    device = FakeDevice()
    device.session.auto_emit = {
        "type": "send",
        "payload": {"type": "status", "message": "ok"},
    }
    _patch(monkeypatch, device)
    result = hooks.create_simple_hook(100, hook_type="network")
    listing = hooks.list_hooks()
    assert listing == [
        {
            "hook_id": result["hook_id"],
            "process_id": 100,
            "hook_type": "network",
            "buffered_messages": 1,
        }
    ]
