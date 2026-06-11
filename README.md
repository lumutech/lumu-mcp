# 🛡️ Lumu MCP Server

> **Supercharge Claude Desktop with Lumu Defender security incident analysis**

An MCP (Model Context Protocol) server that seamlessly integrates Claude Desktop with the Lumu Defender API, enabling AI-powered security incident analysis and management.

[![PyPI version](https://badge.fury.io/py/lumu-mcp-server.svg)](https://badge.fury.io/py/lumu-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🔍 **Incident Retrieval**: Get security incidents with advanced filtering
- 🎯 **Smart Analysis**: AI-powered incident analysis through Claude
- 📊 **Full Management**: Mark as read, mute, unmute, and close incidents
- 🖥️ **Endpoint Insights**: Analyze affected endpoints and network contacts
- 📈 **Real-time Monitoring**: Track incident updates and activity
- 🔐 **Secure Integration**: Environment-based API key management
- ⚡ **Easy Setup**: One-command installation with pip

## 🚀 Quick Start

### 1. Install

```bash
pip install lumu-mcp-server
```

### 2. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lumu-mcp-server": {
      "command": "lumu-mcp-server",
      "env": {
        "LUMU_DEFENDER_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### 3. Start Using

Ask Claude: _"Get security incidents from Lumu Defender"_

> 💡 **Need help finding your config file?** See [Configuration Locations](#configuration-file-locations) below.

## 🔧 Configuration

### Get Your Lumu Defender API Key

1. Log in to your [Lumu Defender account](https://defender.lumu.io)
2. Navigate to **Settings** → **API Keys**
3. Generate or copy your API key

### Configuration File Locations

- **🍎 macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **🪟 Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **🐧 Linux**: `~/.config/Claude/claude_desktop_config.json`

### Configuration Options

#### Standard Configuration (Recommended)

```json
{
  "mcpServers": {
    "lumu-mcp-server": {
      "command": "lumu-mcp-server",
      "env": {
        "LUMU_DEFENDER_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Alternative Configuration

If the command isn't found, use the Python module directly:

```json
{
  "mcpServers": {
    "lumu-mcp-server": {
      "command": "python",
      "args": ["-m", "lumu_mcp_server.server"],
      "env": {
        "LUMU_DEFENDER_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Activate the Integration

1. **Restart Claude Desktop** completely
2. Look for the **🔌 MCP icon** in Claude Desktop
3. Test with: _"Check the health of the lumu-mcp-server"_

## 💬 Usage Examples

Once configured, you can interact with Lumu Defender through natural language:

### 🩺 Health & Status

- _"Check the health of the lumu-mcp-server"_
- _"Is the Lumu integration working?"_

### 🔍 Incident Discovery

- _"Get security incidents from Lumu Defender"_
- _"Show me open security incidents from the last 30 days"_
- _"Find all C2C and Malware incidents"_
- _"Get incidents with status 'open' or 'muted'"_

### 📋 Incident Analysis

- _"Get details for incident [UUID]"_
- _"Show me the full information about incident abc-123-def"_
- _"Get the context for incident [UUID]"_
- _"Show me related incidents and affected assets"_

### 📝 Incident Management

- _"Add a comment to incident [UUID]: 'Investigating with network team'"_
- _"Mark incident [UUID] as read"_
- _"Mute incident [UUID] with comment 'False positive'"_
- _"Close incident [UUID] with comment 'Threat resolved'"_

### 🖥️ Network Analysis

- _"Get endpoints for incident [UUID]"_
- _"Show me which endpoints were affected by this incident"_
- _"Analyze the network impact of incident abc-123-def"_

### 📊 Real-time Monitoring

- _"Get incident updates from the last 10 minutes"_
- _"Show me what happened in the last hour with incidents"_
- _"Check for recent incident activity"_

### 🔄 Advanced Workflows

- _"Get all open Malware incidents, then show details for the most recent one"_
- _"Find critical incidents that are still open and summarize their impact"_
- _"List all muted C2C incidents and help me decide which to unmute"_
- _"Get incident endpoints and mark the incident as read when done"_

## Available Tools

### 1. `health_check`

Returns the server status and API key configuration status.

### 2. `get_incidents`

Retrieves security incidents with optional filters and pagination support.

**Parameters**:

- `from_date` (optional): Start date in ISO format (default: 7 days ago). Max range: 90 days unless `fetch_all` is true.
- `to_date` (optional): End date in ISO format (default: now)
- `status` (optional): Array of statuses ["open", "muted", "closed"]
- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs
- `page` (optional): Page number for pagination (0-indexed, default: 0)
- `limit` (optional): Number of items per page (default: 50, max: 100)
- `fetch_all` (optional): If true, automatically fetches ALL incidents with pagination. Handles large date ranges by chunking.

**Examples**:

```
# Get incidents with pagination
"Get page 2 of incidents with 20 items per page"

# Get ALL incidents for a date range
"Get all incidents from May 1-31, 2026 with fetch_all=true"

# Get all malware incidents
"Get all Malware incidents with fetch_all=true"
```

### 3. `get_incident_details`

Get detailed information about a specific security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident

**Returns**: Detailed incident information including status, IOCs, recommended actions, and more.

### 4. `get_incident_context`

Get context information for a specific security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `hash_type` (optional): Hash type for filtering context

**Returns**: Context including related incidents, affected assets, threat intelligence, and timeline.

### 5. `comment_incident`

Add a comment to a specific security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `comment` (required): The comment text to add

**Returns**: Confirmation of the comment being added.

### 6. `get_open_incidents`

Retrieve only open security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of open incidents with filtering options.

### 7. `get_muted_incidents`

Retrieve only muted security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of muted incidents with filtering options.

### 8. `get_closed_incidents`

Retrieve only closed security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of closed incidents with filtering options.

### 9. `get_incident_endpoints`

Retrieve endpoints and contacts for a specific security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `endpoints` (optional): Filter by specific endpoint IPs or names
- `labels` (optional): Array of label IDs

**Returns**: Detailed endpoint and contact information for the incident.

### 10. `mark_incident_as_read`

Mark a security incident as read.

**Parameters**:

- `incident_id` (required): The UUID of the incident to mark as read

**Returns**: Confirmation that the incident was marked as read.

### 11. `mute_incident`

Mute a security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident to mute
- `comment` (optional): Comment explaining why the incident was muted

**Returns**: Confirmation that the incident was muted.

### 12. `unmute_incident`

Unmute a security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident to unmute
- `comment` (optional): Comment explaining why the incident was unmuted

**Returns**: Confirmation that the incident was unmuted.

### 13. `get_incident_updates`

Get real-time updates on incident operations (alternative to WebSocket).

**Parameters**:

- `offset` (optional): Starting offset for pagination (default: 0)
- `items` (optional): Number of items to return, 1-100 (default: 50)
- `time` (optional): Time window in minutes for updates (default: 5)

**Returns**: List of incident updates with timestamps in UTC (RFC 3339/ISO 8601 format).

### 14. `close_incident`

Close a security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident to close
- `comment` (optional): Comment explaining why the incident was closed

**Returns**: Confirmation that the incident was closed.

## 🔧 Troubleshooting

### Server Not Appearing in Claude Desktop

1. **Check Claude Desktop logs**: Help → Show Logs
2. **Verify installation**: `pip list | grep lumu-mcp-server`
3. **Test command**: Run `lumu-mcp-server --help` in terminal
4. **Restart Claude Desktop** completely

### API Key Issues

- ✅ Ensure API key is correctly set in `claude_desktop_config.json`
- ✅ Verify API key is valid in [Lumu Defender portal](https://portal.lumu.io)
- ✅ Check Claude Desktop logs for authentication errors
- ✅ Test with: _"Check the health of the lumu-mcp-server"_

### No Incidents Returned

- 📅 **Date Range**: Try broader date ranges (e.g., last 30 days)
- 🔍 **Filters**: Remove status/type filters to see all incidents
- 🔑 **Permissions**: Ensure API key has proper incident access
- 💡 **Tip**: Ask Claude _"Get incidents from the last 30 days"_

### Connection Issues

- 🌐 **Network**: Verify internet connection to `defender.lumu.io`
- 🔒 **Firewall**: Ensure HTTPS traffic is allowed
- 🚀 **Proxy**: Configure proxy settings if needed

### Need More Help?

- 📖 Check [QUICK_START.md](QUICK_START.md) for simplified setup
- 🐛 [Report issues](https://github.com/jpyoda/lumu-mcp/issues) on GitHub
- 💬 [Ask questions](https://github.com/jpyoda/lumu-mcp/discussions) in discussions

## 🔒 Security & Privacy

- 🔐 **API keys** stored in environment variables, never in code
- 🌐 **HTTPS** encryption for all API communications
- 🚫 **No data storage** - all data fetched in real-time from Lumu
- 🛡️ **Error sanitization** prevents sensitive information leakage
- 📝 **Audit trail** through Lumu Defender's native logging

## 🤝 Contributing

We welcome contributions! Please see our contribution guidelines:

### Quick Development Setup

```bash
git clone https://github.com/jpyoda/lumu-mcp.git
cd lumu-mcp-server
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Adding New Features

1. **API Methods**: Add to `lumu_mcp_server/lumu_client.py`
2. **Tool Registration**: Update `handle_list_tools()` in `server.py`
3. **Handler Implementation**: Add to `handle_call_tool()` in `server.py`
4. **Testing**: Ensure functionality works with real API

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

### Get Help

- 🚀 **Quick Setup**: [QUICK_START.md](QUICK_START.md)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/jpyoda/lumu-mcp/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/jpyoda/lumu-mcp/discussions)
- 📧 **Lumu API Issues**: [Contact Lumu Support](https://help.lumu.io)

### Project Stats

![GitHub stars](https://img.shields.io/github/stars/jpyoda/lumu-mcp?style=social)
![GitHub forks](https://img.shields.io/github/forks/jpyoda/lumu-mcp?style=social)
![GitHub issues](https://img.shields.io/github/issues/jpyoda/lumu-mcp)

---

**Built with ❤️ for the cybersecurity community**  
_Enhance your security operations with AI-powered incident analysis_
