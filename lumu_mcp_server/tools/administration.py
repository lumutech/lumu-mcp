"""Administration tools (labels)."""

from __future__ import annotations

import logging

from mcp.server.mcpserver import Context, MCPServer

from ..context import get_client

logger = logging.getLogger(__name__)


def register(mcp: MCPServer) -> None:
    """Register administration tools on the server."""

    @mcp.tool()
    async def list_labels(ctx: Context, page: int = 0, limit: int = 50) -> str:
        """List labels configured in the Lumu account.

        Label IDs are used by incident filters (the ``labels`` parameter on the
        incident tools).

        Args:
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        client = get_client(ctx)
        try:
            result = await client.get_labels(page=page, limit=limit)
            labels = result.get("labels", [])
            total = len(labels)

            if total == 0:
                return "No labels found."

            message = f"🏷️ Labels\n\nFound {total} label(s)\n"
            for label in labels:
                message += f"\n  ID: {label.get('id', 'N/A')}\n"
                message += f"  Name: {label.get('name', 'N/A')}\n"
                if label.get("relevance") is not None:
                    message += f"  Relevance: {label.get('relevance')}\n"
            return message

        except ValueError as e:
            return f"❌ Error: {e!s}"
        except Exception as e:
            logger.error("Error calling list_labels: %s", e, exc_info=True)
            return f"❌ Error retrieving labels: {e!s}"

    @mcp.tool()
    async def get_label(ctx: Context, label_id: int) -> str:
        """Get a specific label by ID.

        Args:
            label_id: The numeric ID of the label.
        """
        client = get_client(ctx)
        try:
            label = await client.get_label(label_id)
            message = f"🏷️ Label {label_id}\n\n"
            message += f"  Name: {label.get('name', 'N/A')}\n"
            if label.get("relevance") is not None:
                message += f"  Relevance: {label.get('relevance')}\n"
            return message
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return f"❌ Label not found: {label_id}"
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling get_label: %s", e, exc_info=True)
            return f"❌ Error retrieving label: {e!s}"
