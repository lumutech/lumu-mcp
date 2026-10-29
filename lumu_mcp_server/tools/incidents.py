"""Incident query and inspection tools.

These tools read from the Lumu Defender API and format results as human/model
readable text. Expected, actionable failures (not-found, bad input, config) are
returned as ``❌`` text so the model gets a usable hint; unexpected failures are
logged and surfaced as a short error string.
"""

from __future__ import annotations

import logging
from datetime import datetime

from mcp.server.mcpserver import Context, MCPServer

from ..context import get_client

logger = logging.getLogger(__name__)


def _parse_date(value: str) -> datetime:
    """Parse an ISO-8601 date string, tolerating a trailing 'Z'."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def register(mcp: MCPServer) -> None:
    """Register incident query tools on the server."""

    @mcp.tool()
    async def get_incidents(
        ctx: Context,
        from_date: str | None = None,
        to_date: str | None = None,
        status: list[str] | None = None,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
        fetch_all: bool = False,
    ) -> str:
        """Retrieve security incidents from Lumu Defender API with pagination support.

        Args:
            from_date: Start date in ISO format (e.g. 2024-01-01T00:00:00Z).
                Default: 7 days ago. Max range: 90 days unless fetch_all is true.
            to_date: End date in ISO format. Default: now.
            status: Filter by incident status (open, muted, closed).
            adversary_types: Filter by adversary types
                (C2C, Malware, DGA, Mining, Spam, Phishing).
            labels: Filter by label IDs.
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
            fetch_all: If true, automatically fetch ALL incidents, chunking large
                date ranges.
        """
        client = get_client(ctx)
        try:
            parsed_from = _parse_date(from_date) if from_date else None
            parsed_to = _parse_date(to_date) if to_date else None

            if fetch_all:
                large_range = (
                    parsed_from is not None
                    and parsed_to is not None
                    and (parsed_to - parsed_from).days > client.MAX_DATE_RANGE_DAYS
                )
                if large_range:
                    result = await client.get_all_incidents_chunked(
                        from_date=parsed_from,
                        to_date=parsed_to,
                        status=status,
                        adversary_types=adversary_types,
                        labels=labels,
                    )
                else:
                    result = await client.get_all_incidents(
                        from_date=parsed_from,
                        to_date=parsed_to,
                        status=status,
                        adversary_types=adversary_types,
                        labels=labels,
                    )
            else:
                result = await client.get_incidents(
                    from_date=parsed_from,
                    to_date=parsed_to,
                    status=status,
                    adversary_types=adversary_types,
                    labels=labels,
                    page=page,
                    limit=limit,
                )

            incidents = result.get("incidents", [])
            total = len(incidents)
            pagination = result.get("pagination", {})

            if total == 0:
                from_str = (
                    parsed_from.strftime("%Y-%m-%d") if parsed_from else "default (7 days ago)"
                )
                to_str = parsed_to.strftime("%Y-%m-%d") if parsed_to else "now"
                message = "No incidents found for the specified criteria.\n\nSearch parameters:\n"
                message += f"• Date range: {from_str} to {to_str}\n"
                if status:
                    message += f"• Status filter: {status}\n"
                if adversary_types:
                    message += f"• Adversary types: {adversary_types}\n"
                message += (
                    "\nTip: Try a broader date range or use fetch_all=true to get all incidents."
                )
                return message

            status_counts: dict[str, int] = {}
            type_counts: dict[str, int] = {}
            for incident in incidents:
                incident_status = incident.get("status", "unknown")
                status_counts[incident_status] = status_counts.get(incident_status, 0) + 1
                adv_type = incident.get("adversaryType", "unknown")
                type_counts[adv_type] = type_counts.get(adv_type, 0) + 1

            message = f"Found {total} incident(s)\n\n"

            if fetch_all:
                if result.get("chunks_processed"):
                    message += f"📊 Fetched across {result['chunks_processed']} date chunks\n"
                if result.get("pages_fetched"):
                    message += f"📊 Fetched across {result['pages_fetched']} pages\n"
            else:
                has_more = pagination.get("has_more", False)
                if has_more:
                    message += f"📄 Page {page + 1} (showing {total} of more available)\n"
                    message += (
                        f"💡 Use page={page + 1} for next page, "
                        "or fetch_all=true for all incidents\n"
                    )
                else:
                    message += f"📄 Page {page + 1} (complete results)\n"

            message += "\nStatus breakdown:\n"
            for incident_status, count in status_counts.items():
                message += f"  • {incident_status}: {count}\n"

            message += "\nAdversary type breakdown:\n"
            for adv_type, count in type_counts.items():
                message += f"  • {adv_type}: {count}\n"

            message += "\nRecent incidents:\n"
            for incident in incidents[:5]:
                message += f"\n  ID: {incident.get('id', 'N/A')}\n"
                message += f"  Status: {incident.get('status', 'N/A')}\n"
                message += f"  Type: {incident.get('adversaryType', 'N/A')}\n"
                message += f"  First seen: {incident.get('firstSeen', 'N/A')}\n"
                desc = incident.get("description", "N/A")
                if desc and len(desc) > 100:
                    desc = desc[:100] + "..."
                message += f"  Description: {desc}\n"

            if total > 5:
                message += f"\n... and {total - 5} more incidents"

            return message

        except ValueError as e:
            error_msg = str(e)
            if "exceeds maximum" in error_msg:
                error_msg += (
                    "\n\n💡 Tip: Use fetch_all=true to automatically handle large date ranges."
                )
            return f"❌ Configuration error: {error_msg}"
        except Exception as e:
            logger.error("Error calling get_incidents: %s", e, exc_info=True)
            return f"❌ Error retrieving incidents: {e!s}"

    @mcp.tool()
    async def get_incident_details(ctx: Context, incident_id: str) -> str:
        """Get detailed information about a specific security incident.

        Args:
            incident_id: The UUID of the incident to retrieve details for.
        """
        client = get_client(ctx)
        try:
            result = await client.get_incident_details(incident_id)
            incident = result.get("incident", {})

            message = f"📋 Incident Details: {incident_id}\n\n"
            message += f"Status: {incident.get('status', 'N/A')}\n"

            adv_types = incident.get("adversaryTypes", [])
            if adv_types:
                message += f"Adversary Type: {', '.join(adv_types)}\n"
            else:
                message += "Adversary Type: N/A\n"

            message += f"Timestamp: {incident.get('timestamp', 'N/A')}\n"
            message += f"Last Contact: {incident.get('lastContact', 'N/A')}\n"
            message += f"Total Contacts: {incident.get('contacts', 0)}\n"
            message += f"Total Endpoints: {incident.get('totalEndpoints', 0)}\n"
            message += f"Unread: {incident.get('isUnread', False)}\n"

            if incident.get("description"):
                message += f"\nDescription:\n{incident['description']}\n"

            if incident.get("adversaries"):
                message += "\nAdversaries:\n"
                for adv in incident["adversaries"]:
                    message += f"  • {adv}\n"

            if incident.get("actions"):
                message += "\nRecommended Actions:\n"
                for action in incident["actions"]:
                    message += f"  • {action}\n"

            if incident.get("firstContactDetails"):
                fcd = incident["firstContactDetails"]
                message += "\nFirst Contact Details:\n"
                message += f"  Host: {fcd.get('host', 'N/A')}\n"
                message += (
                    f"  Endpoint: {fcd.get('endpointName', 'N/A')} "
                    f"({fcd.get('endpointIp', 'N/A')})\n"
                )
                message += f"  DateTime: {fcd.get('datetime', 'N/A')}\n"

            return message

        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                api_response = ""
                if "API Response" in error_msg:
                    api_response = f"\n\nAPI Response:\n{error_msg.split('API Response')[1]}"
                return (
                    f"❌ Incident not found: {incident_id}\n\n"
                    "This incident ID doesn't exist or is not accessible. Please:\n"
                    "1. Verify the incident ID is correct\n"
                    "2. Check if the incident exists in your Lumu dashboard\n"
                    "3. Ensure your API key has access to this incident\n"
                    f"4. Use 'get_incidents' to list available incidents{api_response}"
                )
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling get_incident_details: %s", e, exc_info=True)
            return f"❌ Error retrieving incident details: {e!s}"

    @mcp.tool()
    async def get_incident_events_groupings(
        ctx: Context,
        incident_id: str,
        status: list[str] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> str:
        """Retrieve the event groupings of a specific security incident.

        Event groupings bundle the raw security events of an incident. Use the
        returned grouping IDs with get_security_event_details to inspect raw data.

        Args:
            incident_id: The UUID of the incident.
            status: Filter by event grouping status (open, muted, closed).
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        client = get_client(ctx)
        try:
            result = await client.get_incident_events_groupings(
                incident_id, status=status, page=page, limit=limit
            )
            items = result.get("items", [])
            total = len(items)

            if total == 0:
                return f"No event groupings found for incident {incident_id}."

            message = f"🧩 Event Groupings: {incident_id}\n\nFound {total} grouping(s)\n"
            for group in items[:20]:
                group_id = group.get("eventsGroupingId", group.get("id", "N/A"))
                message += f"\n  Grouping ID: {group_id}\n"
                if group.get("status"):
                    message += f"  Status: {group.get('status')}\n"
                if group.get("label"):
                    message += f"  Label: {group.get('label')}\n"
                if group.get("total") is not None:
                    message += f"  Events: {group.get('total')}\n"
            if total > 20:
                message += f"\n... and {total - 20} more groupings"
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
            logger.error("Error calling get_incident_events_groupings: %s", e, exc_info=True)
            return f"❌ Error retrieving event groupings: {e!s}"

    @mcp.tool()
    async def get_security_event_details(
        ctx: Context,
        incident_id: str,
        event_id: str,
        sort: str = "asc",
        page: int = 0,
        limit: int = 50,
    ) -> str:
        """Retrieve the raw data of a specific event group within an incident.

        Args:
            incident_id: The UUID of the incident.
            event_id: The event-grouping ID (from get_incident_events_groupings).
            sort: Sort order for the raw events ("asc" or "desc"). Default: asc.
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        client = get_client(ctx)
        try:
            result = await client.get_security_event_details(
                incident_id, event_id, sort=sort, page=page, limit=limit
            )
            items = result.get("items", [])
            total = len(items)

            message = f"🔬 Security Event Details: incident {incident_id}, group {event_id}\n\n"

            summary = result.get("summary")
            if summary:
                message += f"Summary: {summary}\n\n"

            if total == 0:
                return message + "No raw events found for this event group."

            message += f"Showing {total} raw event(s):\n"
            for event in items[:20]:
                timestamp = event.get("timestamp", event.get("datetime", "N/A"))
                message += f"\n🔸 {timestamp}\n"
                for field in ("host", "endpointName", "endpointIp", "type", "adversaryType"):
                    if event.get(field):
                        message += f"   {field}: {event.get(field)}\n"
            if total > 20:
                message += f"\n... and {total - 20} more events"
            return message

        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return (
                    f"❌ Not found: incident {incident_id} or event group {event_id}\n\n"
                    "Verify the incident ID and the event-grouping ID are correct."
                )
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error calling get_security_event_details: %s", e, exc_info=True)
            return f"❌ Error retrieving security event details: {e!s}"

    @mcp.tool()
    async def get_incident_updates(
        ctx: Context, offset: int = 0, items: int = 50, time: int = 5
    ) -> str:
        """Get real-time updates on incident operations (long-poll).

        Args:
            offset: Starting offset for pagination (default: 0).
            items: Number of items to return (default: 50).
            time: Maximum seconds the server waits for updates (default: 5).
        """
        client = get_client(ctx)
        try:
            result = await client.get_incident_updates(offset, items, time)
            updates = result.get("updates", [])
            total = len(updates)

            message = "📊 Incident Updates\n\n"

            if total == 0:
                message += (
                    "No incident updates found.\n\n"
                    "This indicates no recent incident activity. Try increasing the wait "
                    "time or check your Lumu dashboard for activity."
                )
                return message

            message += f"Found {total} update(s)\n\n"

            update_types: dict[str, list] = {}
            for update in updates:
                update_type = update.get("type", "unknown")
                update_types.setdefault(update_type, []).append(update)

            message += "Update types:\n"
            for update_type, type_updates in update_types.items():
                message += f"  • {update_type}: {len(type_updates)}\n"

            message += "\nRecent updates:\n"
            for update in updates[:10]:
                message += f"\n🔔 {update.get('timestamp', 'N/A')}\n"
                message += f"   Type: {update.get('type', 'N/A')}\n"
                message += f"   Incident: {update.get('incidentId', 'N/A')}\n"
                if update.get("description"):
                    message += f"   Description: {update.get('description')[:100]}...\n"
                if update.get("user"):
                    message += f"   User: {update.get('user')}\n"

            if total > 10:
                message += f"\n... and {total - 10} more updates"

            if result.get("hasMore"):
                message += (
                    f"\n\n📄 More updates available. "
                    f"Use offset={offset + items} to get next page."
                )

            return message

        except ValueError as e:
            return f"❌ Error: {e!s}"
        except Exception as e:
            logger.error("Error calling get_incident_updates: %s", e, exc_info=True)
            return f"❌ Error retrieving incident updates: {e!s}"

    # Status-specific listings share one formatter.
    def _format_status_listing(
        status_name: str,
        result: dict,
        adversary_types: list[str] | None,
        labels: list[int] | None,
        page: int,
    ) -> str:
        incidents = result.get("incidents", [])
        total = len(incidents)
        pagination = result.get("pagination", {})

        if total == 0:
            message = (
                f"No {status_name} incidents found for the specified criteria.\n\n"
                "Search parameters:\n"
            )
            if adversary_types:
                message += f"• Adversary types: {adversary_types}\n"
            if labels:
                message += f"• Labels: {labels}\n"
            message += (
                f"\nTip: Try removing filters or check if there are any {status_name} "
                "incidents in your Lumu dashboard."
            )
            return message

        type_counts: dict[str, int] = {}
        for incident in incidents:
            for adv_type in incident.get("adversaryTypes", []):
                type_counts[adv_type] = type_counts.get(adv_type, 0) + 1

        message = f"Found {total} {status_name} incident(s)\n\n"
        if pagination.get("has_more", False):
            message += f"📄 Page {page + 1} (showing {total} of more available)\n"
            message += f"💡 Use page={page + 1} for next page\n\n"
        else:
            message += f"📄 Page {page + 1} (complete results)\n\n"

        if type_counts:
            message += "Adversary type breakdown:\n"
            for adv_type, count in type_counts.items():
                message += f"  • {adv_type}: {count}\n"

        message += f"\nRecent {status_name} incidents:\n"
        for incident in incidents[:5]:
            message += f"\n  ID: {incident.get('id', 'N/A')}\n"
            adv_types = incident.get("adversaryTypes", [])
            message += f"  Types: {', '.join(adv_types) if adv_types else 'N/A'}\n"
            message += f"  Timestamp: {incident.get('timestamp', 'N/A')}\n"
            desc = incident.get("description", "N/A")
            if desc and len(desc) > 100:
                desc = desc[:100] + "..."
            message += f"  Description: {desc}\n"

        if total > 5:
            message += f"\n... and {total - 5} more incidents"
        return message

    async def _status_listing(
        status_name: str,
        fetch,
        adversary_types: list[str] | None,
        labels: list[int] | None,
        page: int,
        limit: int,
    ) -> str:
        try:
            result = await fetch(
                adversary_types=adversary_types, labels=labels, page=page, limit=limit
            )
            return _format_status_listing(status_name, result, adversary_types, labels, page)
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return f"❌ No {status_name} incidents found or access denied."
            return f"❌ Error: {error_msg}"
        except Exception as e:
            logger.error("Error listing %s incidents: %s", status_name, e, exc_info=True)
            return f"❌ Error retrieving {status_name} incidents: {e!s}"

    @mcp.tool()
    async def get_open_incidents(
        ctx: Context,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> str:
        """Retrieve open security incidents from Lumu Defender with pagination support.

        Args:
            adversary_types: Filter by adversary types.
            labels: Filter by label IDs.
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        return await _status_listing(
            "open", get_client(ctx).get_open_incidents, adversary_types, labels, page, limit
        )

    @mcp.tool()
    async def get_muted_incidents(
        ctx: Context,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> str:
        """Retrieve muted security incidents from Lumu Defender with pagination support.

        Args:
            adversary_types: Filter by adversary types.
            labels: Filter by label IDs.
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        return await _status_listing(
            "muted", get_client(ctx).get_muted_incidents, adversary_types, labels, page, limit
        )

    @mcp.tool()
    async def get_closed_incidents(
        ctx: Context,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> str:
        """Retrieve closed security incidents from Lumu Defender with pagination support.

        Args:
            adversary_types: Filter by adversary types.
            labels: Filter by label IDs.
            page: Page number for pagination (0-indexed). Default: 0.
            limit: Items per page. Default: 50, max: 100.
        """
        return await _status_listing(
            "closed", get_client(ctx).get_closed_incidents, adversary_types, labels, page, limit
        )
