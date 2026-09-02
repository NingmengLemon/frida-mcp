"""Tests for the USB-first device selection policy."""

from __future__ import annotations

import logging

import frida

from frida_mcp import devices


def test_default_device_prefers_usb(monkeypatch) -> None:
    usb = object()

    def boom() -> object:
        raise AssertionError("local device must not be consulted")

    monkeypatch.setattr(devices.frida, "get_usb_device", lambda: usb)
    monkeypatch.setattr(devices.frida, "get_local_device", boom)
    assert devices.default_device() is usb


def test_default_device_falls_back_to_local(monkeypatch, caplog) -> None:
    local = object()

    def no_usb() -> object:
        raise frida.InvalidArgumentError("device not found")

    monkeypatch.setattr(devices.frida, "get_usb_device", no_usb)
    monkeypatch.setattr(devices.frida, "get_local_device", lambda: local)
    with caplog.at_level(logging.WARNING):
        assert devices.default_device() is local
    assert "USB device unavailable" in caplog.text


def test_resolve_device_with_id(monkeypatch) -> None:
    monkeypatch.setattr(
        devices.frida, "get_device", lambda device_id: f"device:{device_id}"
    )
    assert devices.resolve_device("abc") == "device:abc"


def test_resolve_device_defaults(monkeypatch) -> None:
    monkeypatch.setattr(devices, "default_device", lambda: "default")
    assert devices.resolve_device(None) == "default"
