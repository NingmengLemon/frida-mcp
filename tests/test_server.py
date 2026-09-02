"""Tests for the server factory: registration of tools/resources/prompts."""

from __future__ import annotations

from frida_mcp.resources import _EXAMPLE_HOOK
from frida_mcp.server import create_server

EXPECTED_TOOLS = {
    "add_remote_device",
    "attach_to_process",
    "close_session",
    "create_interactive_session",
    "create_simple_hook",
    "enumerate_devices",
    "enumerate_processes",
    "execute_in_session",
    "get_device",
    "get_hook_messages",
    "get_local_device",
    "get_process_by_name",
    "get_session_messages",
    "get_usb_device",
    "kill_process",
    "list_hooks",
    "list_processes",
    "list_sessions",
    "remove_hook",
    "remove_remote_device",
    "resume_process",
    "spawn_process",
}


def test_tools_registered() -> None:
    mcp = create_server()
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert names >= EXPECTED_TOOLS


def test_resources_registered() -> None:
    mcp = create_server()
    uris = {str(r.uri) for r in mcp._resource_manager.list_resources()}
    assert uris >= {
        "frida://version",
        "frida://processes",
        "frida://devices",
        "frida://example/hook",
    }


def test_prompts_registered() -> None:
    mcp = create_server()
    names = {p.name for p in mcp._prompt_manager.list_prompts()}
    assert names >= {
        "analyze_app_prompt",
        "inject_script_prompt",
        "analyze_process_prompt",
    }


def test_example_hook_uses_frida17_api() -> None:
    # The frida 17 compatible API is used; the comment may mention the old name.
    assert "Module.getGlobalExportByName" in _EXAMPLE_HOOK
    assert "Module.findExportByName(" not in _EXAMPLE_HOOK
