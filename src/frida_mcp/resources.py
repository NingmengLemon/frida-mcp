"""MCP resources exposing frida state and an example hook script."""

from __future__ import annotations

import frida
from mcp.server.fastmcp import FastMCP

from frida_mcp.devices import default_device

_EXAMPLE_HOOK = """'use strict';
// Example Frida hook script (frida >= 17).
// frida 17 removed the static Module.findExportByName API; use
// Module.getGlobalExportByName() wrapped in try/catch, since it raises when
// the export does not exist globally.

function hookGlobal(names, callbacks) {
  for (var i = 0; i < names.length; i++) {
    var target = null;
    try { target = Module.getGlobalExportByName(names[i]); } catch (e) { target = null; }
    if (target !== null) {
      Interceptor.attach(target, callbacks);
      console.log('[+] hooked ' + names[i] + ' at ' + target);
      return names[i];
    }
  }
  console.log('[-] none of ' + names.join(', ') + ' found');
  return null;
}

hookGlobal(['open', 'open64', '_open'], {
  onEnter: function (args) {
    var path = '<unreadable>';
    try { path = args[0].readUtf8String(); } catch (e) { }
    console.log('[+] open(' + path + ')');
    this.path = path;
  },
  onLeave: function (retval) {
    console.log('[+] open(' + this.path + ') returned: ' + retval);
  }
});

hookGlobal(['connect'], {
  onEnter: function () {
    console.log('[+] connect() called');
  },
  onLeave: function (retval) {
    console.log('[+] connect() returned: ' + retval);
  }
});

send({ type: 'status', message: 'Hooks installed' });"""


def get_version() -> str:
    """Get the Frida version."""
    return frida.__version__


def get_processes_resource() -> str:
    """Get a list of all processes on the default device as a readable string."""
    processes = default_device().enumerate_processes()
    return "\n".join(f"PID: {p.pid}, Name: {p.name}" for p in processes)


def get_devices_resource() -> str:
    """Get a list of all devices as a readable string."""
    devices = frida.enumerate_devices()
    return "\n".join(f"ID: {d.id}, Name: {d.name}, Type: {d.type}" for d in devices)


def get_example_hook() -> str:
    """Get an example Frida hook script (frida >= 17 compatible)."""
    return _EXAMPLE_HOOK


def register(mcp: FastMCP) -> None:
    mcp.resource("frida://version")(get_version)
    mcp.resource("frida://processes")(get_processes_resource)
    mcp.resource("frida://devices")(get_devices_resource)
    mcp.resource("frida://example/hook")(get_example_hook)
