"""Shared request context for tools.

The server lifespan constructs an :class:`AppContext` once and the SDK exposes
it to every tool via ``ctx.request_context.lifespan_context``. Tools reach their
dependencies through :func:`get_client` rather than any module-level global.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.mcpserver import Context

from .services import LumuDefenderClient


@dataclass
class AppContext:
    """Dependencies shared across all tool invocations."""

    client: LumuDefenderClient


def get_client(ctx: Context) -> LumuDefenderClient:
    """Return the Lumu client injected by the server lifespan."""
    return ctx.request_context.lifespan_context.client
