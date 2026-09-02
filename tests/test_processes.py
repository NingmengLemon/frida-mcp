"""Tests for process management tools (faked devices)."""

from __future__ import annotations

import frida

from frida_mcp.tools import processes
from tests.conftest import FakeDevice, FakeProcess


def _make_device() -> FakeDevice:
    return FakeDevice(
        processes=[FakeProcess(1, "init"), FakeProcess(2222, "com.example.app")]
    )


def test_list_processes_uses_default_device(monkeypatch) -> None:
    device = _make_device()
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    assert processes.list_processes() == [
        {"pid": 1, "name": "init"},
        {"pid": 2222, "name": "com.example.app"},
    ]


def test_enumerate_processes_passes_device_id(monkeypatch) -> None:
    seen: list[str | None] = []
    device = _make_device()

    def resolve(device_id: str | None) -> FakeDevice:
        seen.append(device_id)
        return device

    monkeypatch.setattr(processes, "resolve_device", resolve)
    processes.enumerate_processes("usb-device")
    assert seen == ["usb-device"]


def test_get_process_by_name_found(monkeypatch) -> None:
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: _make_device())
    assert processes.get_process_by_name("example") == {
        "pid": 2222,
        "name": "com.example.app",
        "found": True,
    }


def test_get_process_by_name_not_found(monkeypatch) -> None:
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: _make_device())
    result = processes.get_process_by_name("nope")
    assert result["found"] is False
    assert "nope" in result["error"]


def test_attach_to_process_verifies_and_detaches(monkeypatch) -> None:
    device = _make_device()
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    result = processes.attach_to_process(2222)
    assert result == {"pid": 2222, "success": True, "is_detached": True}
    assert device.attached == [2222]
    assert device.session.is_detached is True


def test_attach_to_process_reports_failure(monkeypatch) -> None:
    device = _make_device()
    device.attach_error = frida.ProcessNotFoundError("gone")
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    result = processes.attach_to_process(999)
    assert result == {"success": False, "error": "gone"}


def test_spawn_process_uses_argv(monkeypatch) -> None:
    device = _make_device()
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    result = processes.spawn_process("com.example.app", args=["--flag", "x"])
    assert result == {"success": True, "pid": 4242}
    assert device.spawned == [("com.example.app", ["--flag", "x"])]


def test_spawn_process_failure(monkeypatch) -> None:
    device = _make_device()
    device.spawn_error = frida.ExecutableNotFoundError("nope")
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    result = processes.spawn_process("nope")
    assert result["success"] is False


def test_resume_and_kill(monkeypatch) -> None:
    device = _make_device()
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    assert processes.resume_process(2222) == {"success": True, "pid": 2222}
    assert processes.kill_process(2222) == {"success": True, "pid": 2222}
    assert device.resumed == [2222]
    assert device.killed == [2222]


def test_resume_failure(monkeypatch) -> None:
    device = _make_device()
    device.resume_error = frida.InvalidArgumentError("bad pid")
    monkeypatch.setattr(processes, "resolve_device", lambda device_id: device)
    result = processes.resume_process(1)
    assert result["success"] is False
