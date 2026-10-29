"""Tool registration for the Lumu MCP Server.

Each capability area is its own module exposing a ``register(mcp)`` function.
``register_all`` wires them onto the server in :func:`lumu_mcp_server.server.build_server`.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import actions, administration, health, incidents


def register_all(mcp: MCPServer) -> None:
    """Register every tool module on the server."""
    health.register(mcp)
    incidents.register(mcp)
    actions.register(mcp)
    administration.register(mcp)
