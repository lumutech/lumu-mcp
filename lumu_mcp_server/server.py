#!/usr/bin/env python3
"""Lumu MCP Server implementation."""

import sys
import os
import asyncio
import logging
from datetime import datetime
from typing import Optional

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
import mcp.types as types

from .lumu_client import LumuDefenderClient
from .server_handlers import handle_status_based_incidents, handle_get_incident_endpoints, handle_incident_action, handle_get_incident_updates, handle_close_incident

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr  # Important: log to stderr, not stdout
)
logger = logging.getLogger(__name__)

# Create server instance
server = Server("lumu-mcp-server")

# Global client instance (will be initialized with API key from environment)
lumu_client: Optional[LumuDefenderClient] = None


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools."""
    tools = [
        types.Tool(
            name="health_check",
            description="Check the health status of the server",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False
            }
        )
    ]
    
    # Only show Lumu tools if API key is configured
    if os.getenv("LUMU_DEFENDER_API_KEY"):
        tools.extend([
            types.Tool(
                name="get_incidents",
                description="Retrieve security incidents from Lumu Defender API",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "from_date": {
                            "type": "string",
                            "description": "Start date in ISO format (e.g., 2024-01-01T00:00:00Z). Default: 7 days ago"
                        },
                        "to_date": {
                            "type": "string",
                            "description": "End date in ISO format (e.g., 2024-01-08T00:00:00Z). Default: now"
                        },
                        "status": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["open", "muted", "closed"]
                            },
                            "description": "Filter by incident status. If not specified, all statuses are returned"
                        },
                        "adversary_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
                            },
                            "description": "Filter by adversary types. If not specified, all types are returned"
                        },
                        "labels": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Filter by label IDs. If not specified, all labels are returned"
                        }
                    },
                    "required": [],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_incident_details",
                description="Get detailed information about a specific security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to retrieve details for"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_incident_context",
                description="Get context information for a specific security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to retrieve context for"
                        },
                        "hash_type": {
                            "type": "string",
                            "description": "Optional hash type for filtering context"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="comment_incident",
                description="Add a comment to a specific security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to comment on"
                        },
                        "comment": {
                            "type": "string",
                            "description": "The comment text to add to the incident"
                        }
                    },
                    "required": ["incident_id", "comment"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_open_incidents",
                description="Retrieve open security incidents from Lumu Defender",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "adversary_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
                            },
                            "description": "Filter by adversary types. If not specified, all types are returned"
                        },
                        "labels": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Filter by label IDs. If not specified, all labels are returned"
                        }
                    },
                    "required": [],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_muted_incidents",
                description="Retrieve muted security incidents from Lumu Defender",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "adversary_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
                            },
                            "description": "Filter by adversary types. If not specified, all types are returned"
                        },
                        "labels": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Filter by label IDs. If not specified, all labels are returned"
                        }
                    },
                    "required": [],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_closed_incidents",
                description="Retrieve closed security incidents from Lumu Defender",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "adversary_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
                            },
                            "description": "Filter by adversary types. If not specified, all types are returned"
                        },
                        "labels": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Filter by label IDs. If not specified, all labels are returned"
                        }
                    },
                    "required": [],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_incident_endpoints",
                description="Retrieve endpoints and contacts for a specific security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident"
                        },
                        "endpoints": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Filter by specific endpoint IPs or names"
                        },
                        "labels": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Filter by label IDs. If not specified, all labels are returned"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="mark_incident_as_read",
                description="Mark a security incident as read",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to mark as read"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="mute_incident",
                description="Mute a security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to mute"
                        },
                        "comment": {
                            "type": "string",
                            "description": "Optional comment for muting the incident"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="unmute_incident",
                description="Unmute a security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to unmute"
                        },
                        "comment": {
                            "type": "string",
                            "description": "Optional comment for unmuting the incident"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="get_incident_updates",
                description="Get real-time updates on incident operations",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "offset": {
                            "type": "integer",
                            "description": "Starting offset for pagination (default: 0)",
                            "minimum": 0
                        },
                        "items": {
                            "type": "integer",
                            "description": "Number of items to return (default: 50)",
                            "minimum": 1,
                            "maximum": 100
                        },
                        "time": {
                            "type": "integer",
                            "description": "Time window in minutes for updates (default: 5)",
                            "minimum": 1
                        }
                    },
                    "required": [],
                    "additionalProperties": False
                }
            ),
            types.Tool(
                name="close_incident",
                description="Close a security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The UUID of the incident to close"
                        },
                        "comment": {
                            "type": "string",
                            "description": "Optional comment for closing the incident"
                        }
                    },
                    "required": ["incident_id"],
                    "additionalProperties": False
                }
            )
        ])
    
    return tools


@server.call_tool()
async def handle_call_tool(
    name: str, 
    arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution."""
    global lumu_client
    
    logger.info(f"Tool called: {name} with arguments: {arguments}")
    
    if name == "health_check":
        api_status = "✅ API key configured" if os.getenv("LUMU_DEFENDER_API_KEY") else "⚠️ No API key configured"
        return [
            types.TextContent(
                type="text",
                text=f"✅ Server is healthy and running\n{api_status}"
            )
        ]
    
    elif name == "get_incidents":
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
            
            # Parse arguments
            args = arguments or {}
            
            # Parse dates if provided
            from_date = None
            to_date = None
            if "from_date" in args:
                from_date = datetime.fromisoformat(args["from_date"].replace("Z", "+00:00"))
            if "to_date" in args:
                to_date = datetime.fromisoformat(args["to_date"].replace("Z", "+00:00"))
            
            # Get incidents
            result = await lumu_client.get_incidents(
                from_date=from_date,
                to_date=to_date,
                status=args.get("status"),
                adversary_types=args.get("adversary_types"),
                labels=args.get("labels")
            )
            
            # Format response
            incidents = result.get("incidents", [])
            total = len(incidents)
            
            if total == 0:
                # Show helpful information about the search
                from_str = from_date.strftime("%Y-%m-%d") if from_date else "default (7 days ago)"
                to_str = to_date.strftime("%Y-%m-%d") if to_date else "now"
                message = f"No incidents found for the specified criteria.\n\nSearch parameters:\n"
                message += f"• Date range: {from_str} to {to_str}\n"
                if args.get("status"):
                    message += f"• Status filter: {args['status']}\n"
                if args.get("adversary_types"):
                    message += f"• Adversary types: {args['adversary_types']}\n"
                message += f"\nTip: Try a broader date range (e.g., last 30 days) or remove filters to see more results."
            else:
                # Create summary
                status_counts = {}
                type_counts = {}
                
                for incident in incidents:
                    # Count by status
                    status = incident.get("status", "unknown")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    
                    # Count by adversary type
                    adv_type = incident.get("adversaryType", "unknown")
                    type_counts[adv_type] = type_counts.get(adv_type, 0) + 1
                
                message = f"Found {total} incident(s)\n\n"
                
                message += "Status breakdown:\n"
                for status, count in status_counts.items():
                    message += f"  • {status}: {count}\n"
                
                message += "\nAdversary type breakdown:\n"
                for adv_type, count in type_counts.items():
                    message += f"  • {adv_type}: {count}\n"
                
                # Show first few incidents as examples
                message += "\nRecent incidents:\n"
                for incident in incidents[:5]:
                    message += f"\n  ID: {incident.get('id', 'N/A')}\n"
                    message += f"  Status: {incident.get('status', 'N/A')}\n"
                    message += f"  Type: {incident.get('adversaryType', 'N/A')}\n"
                    message += f"  First seen: {incident.get('firstSeen', 'N/A')}\n"
                    message += f"  Description: {incident.get('description', 'N/A')[:100]}...\n"
                
                if total > 5:
                    message += f"\n... and {total - 5} more incidents"
            
            return [
                types.TextContent(
                    type="text",
                    text=message
                )
            ]
            
        except ValueError as e:
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Configuration error: {str(e)}"
                )
            ]
        except Exception as e:
            logger.error(f"Error calling get_incidents: {e}", exc_info=True)
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error retrieving incidents: {str(e)}"
                )
            ]
    
    elif name == "get_incident_details":
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
            
            # Get incident ID from arguments
            args = arguments or {}
            incident_id = args.get("incident_id")
            
            if not incident_id:
                return [
                    types.TextContent(
                        type="text",
                        text="❌ Error: incident_id is required"
                    )
                ]
            
            # Get incident details
            result = await lumu_client.get_incident_details(incident_id)
            
            # Format response
            incident = result.get("incident", {})
            
            message = f"📋 Incident Details: {incident_id}\n\n"
            message += f"Status: {incident.get('status', 'N/A')}\n"
            
            # Handle adversary types (it's an array)
            adv_types = incident.get('adversaryTypes', [])
            if adv_types:
                message += f"Adversary Type: {', '.join(adv_types)}\n"
            else:
                message += f"Adversary Type: N/A\n"
            
            # Use correct field names from the API response
            message += f"Timestamp: {incident.get('timestamp', 'N/A')}\n"
            message += f"Last Contact: {incident.get('lastContact', 'N/A')}\n"
            message += f"Total Contacts: {incident.get('contacts', 0)}\n"
            message += f"Total Endpoints: {incident.get('totalEndpoints', 0)}\n"
            message += f"Unread: {incident.get('isUnread', False)}\n"
            
            if incident.get('description'):
                message += f"\nDescription:\n{incident['description']}\n"
            
            if incident.get('adversaries'):
                message += f"\nAdversaries:\n"
                for adv in incident['adversaries']:
                    message += f"  • {adv}\n"
            
            if incident.get('actions') and len(incident['actions']) > 0:
                message += f"\nRecommended Actions:\n"
                for action in incident['actions']:
                    message += f"  • {action}\n"
            
            if incident.get('firstContactDetails'):
                fcd = incident['firstContactDetails']
                message += f"\nFirst Contact Details:\n"
                message += f"  Host: {fcd.get('host', 'N/A')}\n"
                message += f"  Endpoint: {fcd.get('endpointName', 'N/A')} ({fcd.get('endpointIp', 'N/A')})\n"
                message += f"  DateTime: {fcd.get('datetime', 'N/A')}\n"
            
            return [
                types.TextContent(
                    type="text",
                    text=message
                )
            ]
            
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                # Extract API response if present
                api_response = ""
                if "API Response" in error_msg:
                    api_response = f"\n\nAPI Response:\n{error_msg.split('API Response')[1]}"
                
                return [
                    types.TextContent(
                        type="text",
                        text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist or is not accessible. Please:\n1. Verify the incident ID is correct\n2. Check if the incident exists in your Lumu dashboard\n3. Ensure your API key has access to this incident\n4. Use 'get_incidents' to list available incidents{api_response}"
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
            logger.error(f"Error calling get_incident_details: {e}", exc_info=True)
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error retrieving incident details: {str(e)}"
                )
            ]
    
    elif name == "get_incident_context":
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
            hash_type = args.get("hash_type")
            
            if not incident_id:
                return [
                    types.TextContent(
                        type="text",
                        text="❌ Error: incident_id is required"
                    )
                ]
            
            # Get incident context
            result = await lumu_client.get_incident_context(incident_id, hash_type)
            
            # Format response
            context = result.get("context", {})
            
            message = f"🔍 Incident Context: {incident_id}\n\n"
            
            if context.get('related_incidents'):
                message += f"Related Incidents: {len(context['related_incidents'])}\n"
                for related in context['related_incidents'][:5]:
                    message += f"  • {related.get('id', 'N/A')} - {related.get('adversaryType', 'N/A')}\n"
            
            if context.get('affected_assets'):
                message += f"\nAffected Assets:\n"
                for asset in context['affected_assets'][:10]:
                    message += f"  • {asset.get('hostname', asset.get('ip', 'N/A'))}\n"
            
            if context.get('threat_intelligence'):
                message += f"\nThreat Intelligence:\n"
                ti = context['threat_intelligence']
                if ti.get('reputation'):
                    message += f"  Reputation: {ti['reputation']}\n"
                if ti.get('tags'):
                    message += f"  Tags: {', '.join(ti['tags'])}\n"
            
            if context.get('timeline'):
                message += f"\nTimeline Events: {len(context.get('timeline', []))}\n"
            
            return [
                types.TextContent(
                    type="text",
                    text=message if message != f"🔍 Incident Context: {incident_id}\n\n" else f"🔍 No additional context available for incident {incident_id}"
                )
            ]
            
        except ValueError as e:
            error_msg = str(e)
            if "not found" in error_msg.lower():
                return [
                    types.TextContent(
                        type="text",
                        text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist in your Lumu account. Please:\n1. Verify the incident ID is correct\n2. Check if the incident exists in your Lumu dashboard\n3. Use 'get_incidents' to list available incidents first"
                    )
                ]
            else:
                return [
                    types.TextContent(
                        type="text",
                        text=f"❌ Configuration error: {error_msg}"
                    )
                ]
        except Exception as e:
            logger.error(f"Error calling get_incident_context: {e}", exc_info=True)
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error retrieving incident context: {str(e)}"
                )
            ]
    
    elif name == "comment_incident":
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
            comment = args.get("comment")
            
            if not incident_id:
                return [
                    types.TextContent(
                        type="text",
                        text="❌ Error: incident_id is required"
                    )
                ]
            
            if not comment:
                return [
                    types.TextContent(
                        type="text",
                        text="❌ Error: comment is required"
                    )
                ]
            
            # Add comment to incident
            result = await lumu_client.comment_incident(incident_id, comment)
            
            message = f"✅ Comment added successfully to incident {incident_id}\n\n"
            message += f"Comment: \"{comment}\""
            
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
                        text=f"❌ Incident not found: {incident_id}\n\nThis incident ID doesn't exist in your Lumu account. Please:\n1. Verify the incident ID is correct\n2. Check if the incident exists in your Lumu dashboard\n3. Use 'get_incidents' to list available incidents first"
                    )
                ]
            else:
                return [
                    types.TextContent(
                        type="text",
                        text=f"❌ Configuration error: {error_msg}"
                    )
                ]
        except Exception as e:
            logger.error(f"Error calling comment_incident: {e}", exc_info=True)
            return [
                types.TextContent(
                    type="text",
                    text=f"❌ Error adding comment to incident: {str(e)}"
                )
            ]
    
    elif name in ["get_open_incidents", "get_muted_incidents", "get_closed_incidents"]:
        return await handle_status_based_incidents(name, arguments)
    
    elif name == "get_incident_endpoints":
        return await handle_get_incident_endpoints(arguments)
    
    elif name in ["mark_incident_as_read", "mute_incident", "unmute_incident"]:
        return await handle_incident_action(name, arguments)
    
    elif name == "get_incident_updates":
        return await handle_get_incident_updates(arguments)
    
    elif name == "close_incident":
        return await handle_close_incident(arguments)
    
    else:
        raise ValueError(f"Unknown tool: {name}")


async def run():
    """Run the MCP server."""
    logger.info("Starting Lumu MCP Server...")
    
    # Check if API key is configured
    if os.getenv("LUMU_DEFENDER_API_KEY"):
        logger.info("Lumu Defender API key detected")
    else:
        logger.warning("No Lumu Defender API key configured. Lumu tools will be disabled.")
    
    # Run the server using stdio
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("Server initialized, waiting for connections...")
        
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="lumu-mcp-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                )
            )
        )


def main():
    """Main entry point."""
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()