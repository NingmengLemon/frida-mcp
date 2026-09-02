"""Regression: cancelling an in-flight tool call must not kill the server.

With mcp SDK v1 (fastmcp 3.x) a client cancellation crashed the whole server
with "AssertionError: Request already responded to" (python-sdk issue #1152).
fastmcp 4 is built on the rewritten SDK v2 which handles cancellation; these
tests pin that property so a future dependency bump cannot silently regress.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress

from fastmcp import Client, FastMCP


def _make_server() -> tuple[FastMCP, asyncio.Event]:
    mcp = FastMCP("cancel-test")
    cancelled = asyncio.Event()

    @mcp.tool
    async def slow_async(seconds: float) -> str:
        """Block asynchronously for the given number of seconds."""
        try:
            await asyncio.sleep(seconds)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return "done"

    @mcp.tool
    def slow_sync(seconds: float) -> str:
        """Block synchronously for the given number of seconds."""
        time.sleep(seconds)
        return "done"

    @mcp.tool
    def ping() -> str:
        """Always alive."""
        return "pong"

    return mcp, cancelled


def test_cancelled_async_tool_call_keeps_server_alive() -> None:
    async def scenario() -> None:
        mcp, cancelled = _make_server()
        async with Client(mcp) as client:
            task = asyncio.ensure_future(
                client.call_tool("slow_async", {"seconds": 30})
            )
            await asyncio.sleep(0.5)
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.5)
            assert cancelled.is_set()
            result = await client.call_tool("ping", {})
            assert result.data == "pong"

    asyncio.run(scenario())


def test_cancelled_sync_tool_call_keeps_server_alive() -> None:
    """Cancel a blocking sync tool; the discarded late result must not crash.

    This is the exact scenario that killed mcp SDK v1 servers: the tool thread
    finishes after the request was already cancelled and responded to.
    """

    async def scenario() -> None:
        mcp, _cancelled = _make_server()
        async with Client(mcp) as client:
            task = asyncio.ensure_future(client.call_tool("slow_sync", {"seconds": 2}))
            await asyncio.sleep(0.3)
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            # let the abandoned tool thread finish and its result be discarded
            await asyncio.sleep(2.5)
            result = await client.call_tool("ping", {})
            assert result.data == "pong"

    asyncio.run(scenario())
