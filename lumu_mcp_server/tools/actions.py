"""Incident mutation tools (comment, read, mute/unmute, close)."""

from __future__ import annotations

import logging

from mcp.server.mcpserver import Context, MCPServer

from ..context import get_client

logger = logging.getLogger(__name__)


def register(mcp: MCPServer) -> None:
    """Register incident mutation tools on the server."""

    @mcp.tool()
    async def comment_incident(ctx: Context, incident_id: str, comment: str) -> str:
        """Add a comment to a specific security incident.

        Args:
            incident_id: The UUID of the incident to comment on.
            comment: The comment text to add to the incident.
        """
        client = get_client(ctx)
        try:
            result = await client.comment_incident(incident_id, comment)
            message = f"✅ Comment added successfully to incident {incident_id}\n\n"
            message += f'Comment: "{comment}"'
            if result.get("timestamp"):
                message += f"\nTimestamp: {result['timestamp']}"
            return message
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return (
                    f"❌ Incident not found: {incident_id}\n\n"
                    "This incident ID doesn't exist in your Lumu account. Please:\n"
                    "1. Verify the incident ID is correct\n"
                    "2. Check if the incident exists in your Lumu dashboard\n"
                    "3. Use 'get_incidents' to list available incidents first"
                )
            return f"❌ Configuration error: {error_msg}"
        except Exception as e:
            logger.error("Error calling comment_incident: %s", e, exc_info=True)
            return f"❌ Error adding comment to incident: {e!s}"

    async def _incident_action(ctx: Context, incident_id: str, action: str, comment: str) -> str:
        """Shared handler for mark-as-read / mute / unmute."""
        client = get_client(ctx)
        try:
            if action == "mark_incident_as_read":
                result = await client.mark_incident_as_read(incident_id)
                action_msg, emoji = "marked as read", "👁️"
            elif action == "mute_incident":
                result = await client.mute_incident(incident_id, comment)
                action_msg, emoji = "muted", "🔇"
            else:  # unmute_incident
                result = await client.unmute_incident(incident_id, comment)
                action_msg, emoji = "unmuted", "🔊"

            message = f"{emoji} Incident {action_msg} successfully: {incident_id}"
            if comment:
                message += f'\n\nComment: "{comment}"'
            if result.get("timestamp"):
                message += f"\nTimestamp: {result['timestamp']}"
            return message
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return (
                    f"❌ Incident not found: {incident_id}\n\n"
                    "This incident ID doesn't exist or is not accessible."
                )
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling %s: %s", action, e, exc_info=True)
            return f"❌ Error performing action on incident: {e!s}"

    @mcp.tool()
    async def mark_incident_as_read(ctx: Context, incident_id: str) -> str:
        """Mark a security incident as read.

        Args:
            incident_id: The UUID of the incident to mark as read.
        """
        return await _incident_action(ctx, incident_id, "mark_incident_as_read", "")

    @mcp.tool()
    async def mute_incident(ctx: Context, incident_id: str, comment: str = "") -> str:
        """Mute a security incident.

        Args:
            incident_id: The UUID of the incident to mute.
            comment: Optional comment for muting the incident.
        """
        return await _incident_action(ctx, incident_id, "mute_incident", comment)

    @mcp.tool()
    async def unmute_incident(ctx: Context, incident_id: str, comment: str = "") -> str:
        """Unmute a security incident.

        Args:
            incident_id: The UUID of the incident to unmute.
            comment: Optional comment for unmuting the incident.
        """
        return await _incident_action(ctx, incident_id, "unmute_incident", comment)

    @mcp.tool()
    async def close_incident(ctx: Context, incident_id: str, comment: str = "") -> str:
        """Close a security incident.

        Args:
            incident_id: The UUID of the incident to close.
            comment: Optional comment for closing the incident.
        """
        client = get_client(ctx)
        try:
            result = await client.close_incident(incident_id, comment)
            message = f"🔒 Incident closed successfully: {incident_id}"
            if comment:
                message += f'\n\nComment: "{comment}"'
            if result.get("timestamp"):
                message += f"\nTimestamp: {result['timestamp']}"
            if result.get("closedBy"):
                message += f"\nClosed by: {result['closedBy']}"
            return message
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return (
                    f"❌ Incident not found: {incident_id}\n\n"
                    "This incident ID doesn't exist or is not accessible."
                )
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling close_incident: %s", e, exc_info=True)
            return f"❌ Error closing incident: {e!s}"

    @mcp.tool()
    async def begin_work(ctx: Context, incident_id: str, assignee: int, comment: str = "") -> str:
        """Begin work on a security incident and assign it to a user.

        Args:
            incident_id: The UUID of the incident.
            assignee: The numeric user ID to assign the incident to.
            comment: Optional comment.
        """
        client = get_client(ctx)
        try:
            result = await client.begin_incident_work(incident_id, assignee, comment)
            message = f"🛠️ Work begun on incident {incident_id} (assigned to user {assignee})"
            if comment:
                message += f'\n\nComment: "{comment}"'
            if result.get("timestamp"):
                message += f"\nTimestamp: {result['timestamp']}"
            return message
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return (
                    f"❌ Incident not found: {incident_id}\n\n"
                    "This incident ID doesn't exist or is not accessible."
                )
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling begin_work: %s", e, exc_info=True)
            return f"❌ Error beginning work on incident: {e!s}"
