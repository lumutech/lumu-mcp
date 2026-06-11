"""Additional handlers for new Lumu MCP Server tools."""

import os
import logging
from typing import Optional
import mcp.types as types
from .lumu_client import LumuDefenderClient

logger = logging.getLogger(__name__)

# Global client instance (will be initialized with API key from environment)
lumu_client: Optional[LumuDefenderClient] = None


async def handle_status_based_incidents(tool_name: str, arguments: dict) -> list[types.TextContent]:
    """Handle get_open_incidents, get_muted_incidents, get_closed_incidents."""
    global lumu_client

    # Check if API key is configured
    if not os.getenv("LUMU_DEFENDER_API_KEY"):
        return [
            types.TextContent(
                type="text",
                text="❌ Error: Lumu Defender API key not configured. Please set LUMU_DEFENDER_API_KEY in the Claude Desktop configuration."
            )
        ]

    # Determine status_name early for error handling
    status_name = "unknown"
    if tool_name == "get_open_incidents":
        status_name = "open"
    elif tool_name == "get_muted_incidents":
        status_name = "muted"
    elif tool_name == "get_closed_incidents":
        status_name = "closed"

    try:
        # Initialize client if needed
        if lumu_client is None:
            lumu_client = LumuDefenderClient()

        # Parse arguments
        args = arguments or {}
        adversary_types = args.get("adversary_types")
        labels = args.get("labels")
        page = args.get("page", 0)
        limit = args.get("limit", 50)

        # Call appropriate method based on tool name
        if tool_name == "get_open_incidents":
            result = await lumu_client.get_open_incidents(
                adversary_types=adversary_types, labels=labels, page=page, limit=limit
            )
        elif tool_name == "get_muted_incidents":
            result = await lumu_client.get_muted_incidents(
                adversary_types=adversary_types, labels=labels, page=page, limit=limit
            )
        elif tool_name == "get_closed_incidents":
            result = await lumu_client.get_closed_incidents(
                adversary_types=adversary_types, labels=labels, page=page, limit=limit
            )
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

        # Format response
        incidents = result.get("incidents", [])
        total = len(incidents)
        pagination = result.get("pagination", {})

        if total == 0:
            message = f"No {status_name} incidents found for the specified criteria.\n\nSearch parameters:\n"
            if adversary_types:
                message += f"• Adversary types: {adversary_types}\n"
            if labels:
                message += f"• Labels: {labels}\n"
            message += f"\nTip: Try removing filters or check if there are any {status_name} incidents in your Lumu dashboard."
        else:
            # Create summary
            type_counts = {}

            for incident in incidents:
                # Count by adversary type
                adv_types = incident.get("adversaryTypes", [])
                for adv_type in adv_types:
                    type_counts[adv_type] = type_counts.get(adv_type, 0) + 1

            message = f"Found {total} {status_name} incident(s)\n\n"

            # Add pagination info
            has_more = pagination.get("has_more", False)
            if has_more:
                message += f"📄 Page {page + 1} (showing {total} of more available)\n"
                message += f"💡 Use page={page + 1} for next page\n\n"
            else:
                message += f"📄 Page {page + 1} (complete results)\n\n"

            if type_counts:
                message += "Adversary type breakdown:\n"
                for adv_type, count in type_counts.items():
                    message += f"  • {adv_type}: {count}\n"

            # Show first few incidents as examples
            message += f"\nRecent {status_name} incidents:\n"
            for incident in incidents[:5]:
                message += f"\n  ID: {incident.get('id', 'N/A')}\n"
                adv_types = incident.get('adversaryTypes', [])
                message += f"  Types: {', '.join(adv_types) if adv_types else 'N/A'}\n"
                message += f"  Timestamp: {incident.get('timestamp', 'N/A')}\n"
                desc = incident.get('description', 'N/A')
                if desc and len(desc) > 100:
                    desc = desc[:100] + "..."
                message += f"  Description: {desc}\n"

            if total > 5:
                message += f"\n... and {total - 5} more incidents"

        return [
            types.TextContent(
                type="text",
                text=message
            )
        ]

    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ No {status_name} incidents found or access denied."
                )
            ]
        else:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}"
                )
            ]
    except Exception as e:
        logger.error(f"Error calling {tool_name}: {e}", exc_info=True)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error retrieving {status_name} incidents: {str(e)}"
            )
        ]


async def handle_get_incident_endpoints(arguments: dict) -> list[types.TextContent]:
    """Handle get_incident_endpoints."""
    global lumu_client
    
    # Check if API key is configured
    if not os.getenv("LUMU_DEFENDER_API_KEY"):
        return [
            types.TextContent(
                type="text",
                text="❌ Error: Lumu Defender API key not configured. Please set LUMU_DEFENDER_API_KEY in the Claude Desktop configuration."
            )
        ]
    
    try:
        # Initialize client if needed
        if lumu_client is None:
            lumu_client = LumuDefenderClient()
        
        # Get arguments
        args = arguments or {}
        incident_id = args.get("incident_id")
        endpoints = args.get("endpoints")
        labels = args.get("labels")
        
        if not incident_id:
            return [
                types.TextContent(
                    type="text",
                    text="❌ Error: incident_id is required"
                )
            ]
        
        # Get incident endpoints
        result = await lumu_client.get_incident_endpoints(incident_id, endpoints, labels)
        
        # Format response
        message = f"🖥️ Incident Endpoints: {incident_id}\n\n"
        
        if result.get('contacts'):
            contacts = result['contacts']
            message += f"Total contacts: {len(contacts)}\n\n"
            
            # Group by endpoint
            endpoint_groups = {}
            for contact in contacts:
                endpoint_ip = contact.get('endpointIp', 'Unknown')
                endpoint_name = contact.get('endpointName', 'Unknown')
                endpoint_key = f"{endpoint_name} ({endpoint_ip})"
                
                if endpoint_key not in endpoint_groups:
                    endpoint_groups[endpoint_key] = []
                endpoint_groups[endpoint_key].append(contact)
            
            message += "Endpoints and contacts:\n"
            for endpoint, endpoint_contacts in endpoint_groups.items():
                message += f"\n📍 {endpoint}\n"
                message += f"   Contacts: {len(endpoint_contacts)}\n"
                
                # Show sample contacts
                for contact in endpoint_contacts[:3]:
                    message += f"   • {contact.get('datetime', 'N/A')} - {contact.get('host', 'N/A')}\n"
                
                if len(endpoint_contacts) > 3:
                    message += f"   ... and {len(endpoint_contacts) - 3} more contacts\n"
        
        if result.get('endpoints'):
            endpoints_list = result['endpoints']
            message += f"\n\nUnique endpoints: {len(endpoints_list)}\n"
            for endpoint in endpoints_list[:10]:
                message += f"  • {endpoint.get('name', 'N/A')} ({endpoint.get('ip', 'N/A')})\n"
        
        return [
            types.TextContent(
                type="text",
                text=message if "Total contacts:" in message else f"🖥️ No endpoint data available for incident {incident_id}\n\nThis incident may not have endpoint contact data, or the incident ID may not exist."
            )
        ]
        
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist or is not accessible."
                )
            ]
        else:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}"
                )
            ]
    except Exception as e:
        logger.error(f"Error calling get_incident_endpoints: {e}", exc_info=True)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error retrieving incident endpoints: {str(e)}"
            )
        ]


async def handle_incident_action(tool_name: str, arguments: dict) -> list[types.TextContent]:
    """Handle mark_incident_as_read, mute_incident, unmute_incident."""
    global lumu_client
    
    # Check if API key is configured
    if not os.getenv("LUMU_DEFENDER_API_KEY"):
        return [
            types.TextContent(
                type="text",
                text="❌ Error: Lumu Defender API key not configured. Please set LUMU_DEFENDER_API_KEY in the Claude Desktop configuration."
            )
        ]
    
    try:
        # Initialize client if needed
        if lumu_client is None:
            lumu_client = LumuDefenderClient()
        
        # Get arguments
        args = arguments or {}
        incident_id = args.get("incident_id")
        comment = args.get("comment", "")
        
        if not incident_id:
            return [
                types.TextContent(
                    type="text",
                    text="❌ Error: incident_id is required"
                )
            ]
        
        # Call appropriate method based on tool name
        if tool_name == "mark_incident_as_read":
            result = await lumu_client.mark_incident_as_read(incident_id)
            action_msg = "marked as read"
            emoji = "👁️"
        elif tool_name == "mute_incident":
            result = await lumu_client.mute_incident(incident_id, comment)
            action_msg = "muted"
            emoji = "🔇"
        elif tool_name == "unmute_incident":
            result = await lumu_client.unmute_incident(incident_id, comment)
            action_msg = "unmuted"
            emoji = "🔊"
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        message = f"{emoji} Incident {action_msg} successfully: {incident_id}"
        
        if comment:
            message += f"\n\nComment: \"{comment}\""
        
        if result.get('timestamp'):
            message += f"\nTimestamp: {result['timestamp']}"
        
        return [
            types.TextContent(
                type="text",
                text=message
            )
        ]
        
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist or is not accessible."
                )
            ]
        else:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}"
                )
            ]
    except Exception as e:
        logger.error(f"Error calling {tool_name}: {e}", exc_info=True)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error performing action on incident: {str(e)}"
            )
        ]


async def handle_get_incident_updates(arguments: dict) -> list[types.TextContent]:
    """Handle get_incident_updates."""
    global lumu_client
    
    # Check if API key is configured
    if not os.getenv("LUMU_DEFENDER_API_KEY"):
        return [
            types.TextContent(
                type="text",
                text="❌ Error: Lumu Defender API key not configured. Please set LUMU_DEFENDER_API_KEY in the Claude Desktop configuration."
            )
        ]
    
    try:
        # Initialize client if needed
        if lumu_client is None:
            lumu_client = LumuDefenderClient()
        
        # Get arguments with defaults
        args = arguments or {}
        offset = args.get("offset", 0)
        items = args.get("items", 50)
        time_window = args.get("time", 5)
        
        # Get incident updates
        result = await lumu_client.get_incident_updates(offset, items, time_window)
        
        # Format response
        updates = result.get("updates", [])
        total = len(updates)
        
        message = f"📊 Incident Updates (last {time_window} minutes)\n\n"
        
        if total == 0:
            message += f"No incident updates found in the last {time_window} minutes.\n\nThis indicates no recent incident activity. Try increasing the time window or check your Lumu dashboard for activity."
        else:
            message += f"Found {total} update(s)\n\n"
            
            # Group updates by type
            update_types = {}
            for update in updates:
                update_type = update.get('type', 'unknown')
                if update_type not in update_types:
                    update_types[update_type] = []
                update_types[update_type].append(update)
            
            # Show breakdown by type
            message += "Update types:\n"
            for update_type, type_updates in update_types.items():
                message += f"  • {update_type}: {len(type_updates)}\n"
            
            # Show recent updates
            message += f"\nRecent updates:\n"
            for update in updates[:10]:  # Show first 10
                message += f"\n🔔 {update.get('timestamp', 'N/A')}\n"
                message += f"   Type: {update.get('type', 'N/A')}\n"
                message += f"   Incident: {update.get('incidentId', 'N/A')}\n"
                if update.get('description'):
                    message += f"   Description: {update.get('description')[:100]}...\n"
                if update.get('user'):
                    message += f"   User: {update.get('user')}\n"
            
            if total > 10:
                message += f"\n... and {total - 10} more updates"
            
            # Add pagination info
            if result.get('hasMore'):
                message += f"\n\n📄 More updates available. Use offset={offset + items} to get next page."
        
        return [
            types.TextContent(
                type="text",
                text=message
            )
        ]
        
    except ValueError as e:
        error_msg = str(e)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error: {error_msg}"
            )
        ]
    except Exception as e:
        logger.error(f"Error calling get_incident_updates: {e}", exc_info=True)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error retrieving incident updates: {str(e)}"
            )
        ]


async def handle_close_incident(arguments: dict) -> list[types.TextContent]:
    """Handle close_incident."""
    global lumu_client
    
    # Check if API key is configured
    if not os.getenv("LUMU_DEFENDER_API_KEY"):
        return [
            types.TextContent(
                type="text",
                text="❌ Error: Lumu Defender API key not configured. Please set LUMU_DEFENDER_API_KEY in the Claude Desktop configuration."
            )
        ]
    
    try:
        # Initialize client if needed
        if lumu_client is None:
            lumu_client = LumuDefenderClient()
        
        # Get arguments
        args = arguments or {}
        incident_id = args.get("incident_id")
        comment = args.get("comment", "")
        
        if not incident_id:
            return [
                types.TextContent(
                    type="text",
                    text="❌ Error: incident_id is required"
                )
            ]
        
        # Close the incident
        result = await lumu_client.close_incident(incident_id, comment)
        
        message = f"🔒 Incident closed successfully: {incident_id}"
        
        if comment:
            message += f"\n\nComment: \"{comment}\""
        
        if result.get('timestamp'):
            message += f"\nTimestamp: {result['timestamp']}"
        
        if result.get('closedBy'):
            message += f"\nClosed by: {result['closedBy']}"
        
        return [
            types.TextContent(
                type="text",
                text=message
            )
        ]
        
    except ValueError as e:
        error_msg = str(e)
        if "not found" in error_msg.lower():
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist or is not accessible."
                )
            ]
        else:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}"
                )
            ]
    except Exception as e:
        logger.error(f"Error calling close_incident: {e}", exc_info=True)
        return [
            types.TextContent(
                type="text",
                text=f"❌ Error closing incident: {str(e)}"
            )
        ]