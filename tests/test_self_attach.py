"""Live smoke test against the real local device.

Enabled only with FRIDA_LIVE_TESTS=1 (requires an attachable local process;
on Windows elevation may be needed for cross-process attach).
"""

from __future__ import annotations

import os

import pytest

from frida_mcp.state import hook_registry
from frida_mcp.tools.hooks import create_simple_hook, remove_hook

pytestmark = pytest.mark.skipif(
    os.environ.get("FRIDA_LIVE_TESTS") != "1",
    reason="set FRIDA_LIVE_TESTS=1 to run live tests",
)


def test_memory_hook_roundtrip_on_self() -> None:
    # Explicitly target the local device: default_device() prefers USB and
    # this test runs on the host machine.
    result = create_simple_hook(os.getpid(), hook_type="memory", device_id="local")
    assert result["success"], result
    hook_id = result["hook_id"]
    assert hook_registry.get(hook_id) is not None
    removed = remove_hook(hook_id)
    assert removed["success"] is True
    assert hook_registry.get(hook_id) is None