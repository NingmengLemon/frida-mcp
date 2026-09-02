# Frida MCP

A Model Context Protocol (MCP) implementation for the Frida dynamic instrumentation
toolkit. It exposes process/device management, an interactive JavaScript REPL,
ready-made hooks, and remote frida-server connections as MCP tools so AI systems
(Claude Desktop, Claude Code, ...) can instrument mobile and desktop apps.

Built on the standalone [FastMCP](https://gofastmcp.com) framework (fastmcp 4.x, MCP SDK v2).

This is a hard fork of [dnakov/frida-mcp](https://github.com/dnakov/frida-mcp),
reworked for modern frida 17.x and engineered as a maintainable Python package.

## Requirements

- CPython >= 3.12
- frida >= 17, < 18 (client bindings must match the frida-server version on the device)
- fastmcp >= 4, < 5
- [uv](https://docs.astral.sh/uv/) for development

> Note: frida 17 removed the Java bridge on Android 14+ in some configurations; this
> fork targets native instrumentation (Interceptor / Memory / Module APIs).

## What's new in this fork (0.4.0)

- **frida 17 compatible hooks** — the original `create_simple_hook` scripts used
  `Module.findExportByName()`, which was removed in frida 17. All bundled hook
  scripts and the example resource now use `Module.getGlobalExportByName()` and
  report a proper error when an export does not exist on the target platform.
- **USB-first device policy** — tools without an explicit `device_id` target the
  USB device first (the common Android workflow) and fall back to the local
  device, logging a warning (fixes upstream issue #1).
- **Session & hook lifecycle management** — new tools `list_sessions`,
  `close_session`, `list_hooks`, `get_hook_messages`, and `remove_hook`.
  Registries auto-clean when the target detaches, message queues are capped, and
  sessions survive brief USB disconnects (`persist_timeout`).
- **Remote frida-server support** — `add_remote_device` / `remove_remote_device`
  (fixes upstream issue #6, based on upstream PR #7) with IPv6-aware address
  formatting and optional TLS/auth parameters.
- **frida 17 spawn API** — `spawn_process` now passes arguments via `argv` as
  required by frida 17.
- **Modern package engineering** — split module layout, typed code checked by
  mypy (strict) and ty, linted/formatted by ruff, unit tests with pytest, uv
  dependency groups, and a committed `uv.lock`.
- **Honest error reporting** — operational failures return structured
  `{"success": false, "error": ...}` results instead of crashing the server.
- **FastMCP 3** — migrated from the mcp SDK's bundled FastMCP 1.0 to the
  standalone fastmcp framework. Prompts were removed: tools are the
  interface; every tool ships a description the model reads.
- **FastMCP 4 / SDK v2** — a client cancelling an in-flight tool call used to
  crash the whole server ("Request already responded to", python-sdk issue
  #1152; no fix ever shipped on the 1.x line). fastmcp 4 runs on the rewritten
  MCP SDK v2, which handles cancellation gracefully; regression tests pin
  this behavior for both async and sync tools.

## Installation

```bash
git clone <this-repo>
cd frida-mcp
uv sync            # creates .venv, installs runtime + dev dependencies
uv run frida-mcp   # run the server over stdio
```

or use uv tool / uvx

```bash
uv tool install <this-repo>
frida-mcp
```

## Claude Desktop Integration

Add to your Claude Desktop configuration
(macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows
`%APPDATA%\Claude\claude_desktop_config.json`, Linux
`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "frida": {
      "command": "uv",
      "args": ["run", "frida-mcp"],
      "cwd": "/path/to/frida-mcp"
    }
  }
}
```

## Tools

### Device management

| Tool | Description |
| --- | --- |
| `enumerate_devices` | List all devices (USB, local, remote) |
| `get_device` / `get_usb_device` / `get_local_device` | Get device info by ID / USB / local |
| `add_remote_device` | Connect to a remote frida-server (host, port, TLS/auth) |
| `remove_remote_device` | Disconnect a remote frida-server |

### Process management

| Tool | Description |
| --- | --- |
| `list_processes` / `enumerate_processes` | List processes on the default / a chosen device |
| `get_process_by_name` | Find a process by case-insensitive name substring |
| `attach_to_process` | Verify attachability, then detach immediately |
| `spawn_process` / `resume_process` / `kill_process` | Spawn (suspended), resume, kill |

### Interactive sessions

| Tool | Description |
| --- | --- |
| `create_interactive_session` | Attach and get a session ID |
| `execute_in_session` | Run JavaScript in the target (optionally `keep_alive`) |
| `get_session_messages` | Drain messages from persistent scripts |
| `list_sessions` / `close_session` | Inspect / clean up sessions |

### Ready-made hooks

| Tool | Description |
| --- | --- |
| `create_simple_hook` | Install a memory (>1 MB malloc), file (open), or network (connect) hook |
| `get_hook_messages` | Drain hook output |
| `list_hooks` / `remove_hook` | Inspect / tear down hooks |

Example:

```py
create_simple_hook(pid=1234, hook_type="network")  # -> hook_id
get_hook_messages(hook_id="hook_...")  # -> captured logs
remove_hook(hook_id="hook_...")  # -> unload + detach
```

## Resources

- `frida://version` — frida client version
- `frida://processes` — process list of the default device
- `frida://devices` — device list
- `frida://example/hook` — frida 17 compatible example hook script

## Development

```bash
uv sync                    # install dependencies
uv run pytest              # unit tests (fakes; no device needed)
uv run ruff check .        # lint
uv run ruff format --check .
uv run mypy                # strict type checking
uv run ty check src        # runtime type checking
uv build                   # build sdist + wheel
```

Live smoke tests against a real device:

```bash
FRIDA_LIVE_TESTS=1 uv run pytest tests/test_self_attach.py
```

## Project structure

```txt
src/frida_mcp/
  cli.py            # thin STDIO entry point
  server.py         # create_server() factory
  devices.py        # USB-first device policy
  state.py          # session/hook registries (thread-safe, capped queues)
  resources.py      # frida:// resources
  tools/
    device_tools.py # device + remote connection tools
    processes.py    # process management tools
    sessions.py     # interactive session tools
    hooks.py        # ready-made hooks + lifecycle
tests/              # pytest suite with faked devices
```

## License

MIT