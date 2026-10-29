"""Composition root for the Lumu MCP Server.

``build_server`` turns a validated :class:`AppSettings` into a ready-to-run
:class:`MCPServer`. It performs no environment access itself — all configuration
arrives via the injected settings. The Lumu API client is created once in the
server lifespan (shared across requests) and closed on shutdown.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer

from .config import AppSettings
from .context import AppContext
from .services import LumuDefenderClient
from .tools import register_all

logger = logging.getLogger(__name__)


def build_server(settings: AppSettings) -> MCPServer:
    """Build and configure the MCP server from settings.

    Args:
        settings: Validated application configuration.

    Returns:
        A configured :class:`MCPServer` with all tools registered.
    """

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
        # Build service clients once; shared across all sessions/requests.
        client = LumuDefenderClient(
            api_key=settings.defender_api_key.get_secret_value(),
            base_url=settings.api_base_url,
            timeout=settings.request_timeout,
        )
        logger.info("Lumu Defender client ready (base_url=%s)", settings.api_base_url)
        try:
            yield AppContext(client=client)
        finally:
            await client.aclose()
            logger.info("Lumu Defender client closed")

    mcp = MCPServer(
        settings.name,
        version=settings.version,
        instructions=settings.instructions,
        debug=settings.debug,
        log_level=settings.log_level,
        lifespan=lifespan,
    )
    register_all(mcp)
    return mcp
