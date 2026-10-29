"""Health-check tool."""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer


def register(mcp: MCPServer) -> None:
    """Register the health-check tool on the server."""

    @mcp.tool()
    async def health_check(ctx: Context) -> str:
        """Check the health status of the server."""
        # The server fails fast at startup without an API key, so if we are
        # running the key is configured.
        return "✅ Server is healthy and running\n✅ API key configured"
