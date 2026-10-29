# 🛡️ Lumu MCP Server

> **Supercharge Claude Desktop with Lumu Defender security incident analysis**

An MCP (Model Context Protocol) server that seamlessly integrates Claude Desktop with the Lumu Defender API, enabling AI-powered security incident analysis and management.

[![PyPI version](https://badge.fury.io/py/lumu-mcp-server.svg)](https://badge.fury.io/py/lumu-mcp-server)
[![Python 3.11.18+](https://img.shields.io/badge/python-3.11.18+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🔍 **Incident Retrieval**: Get security incidents with advanced filtering
- 🎯 **Smart Analysis**: AI-powered incident analysis through Claude
- 📊 **Full Management**: Mark as read, mute, unmute, and close incidents
- 🔬 **Event Drill-down**: Inspect incident event groupings and their raw security events
- 📈 **Real-time Monitoring**: Track incident updates and activity
- 🔐 **Secure Integration**: Environment-based API key management
- ⚡ **Easy Setup**: One-command installation with pip

## 🚀 Quick Start

### 1. Install

> **Security requirement (TLS/certificate fixes, Oct 2026):** install into a Python patched
> against CVE-2026-115557 — **3.11.18 / 3.12.16 / 3.13.18 / 3.14.10** or newer — and upgrade pip
> first. A fresh install then pulls a patched `certifi` (≥ 2026.10.19) automatically via `httpx`.
>
> ```bash
> python -m pip install --upgrade pip
> ```

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
      "args": ["-m", "lumu_mcp_server"],
      "env": {
        "LUMU_DEFENDER_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Claude Code (CLI)

If you use Claude Code (the terminal CLI) instead of the Claude Desktop app,
register the server and pass the API key in one command — no JSON file to edit:

```bash
claude mcp add lumu-mcp-server \
  -e LUMU_DEFENDER_API_KEY=your-api-key-here \
  -- lumu-mcp-server
```

- `-e KEY=value` sets the environment variable the server reads.
- `--` separates Claude's own flags from the server command.
- Add `-s user` to make it available in all your projects (default scope is the
  current project). Avoid `-s project` with a real key, since that writes a
  shared `.mcp.json`.

Then run `/mcp` inside a session to confirm it's connected, and remove it later
with `claude mcp remove lumu-mcp-server`.

> **Note:** `claude mcp add` configures **Claude Code** only — it does not affect
> the Claude Desktop app, which reads `claude_desktop_config.json` (above).

### Environment Variables

All variables use the `LUMU_` prefix and are read at startup by a single typed
configuration module. **`LUMU_DEFENDER_API_KEY` is required** — the server fails
fast with a clear message if it is missing. Everything else has a safe default.

| Variable | Purpose | Type | Default | Required | Secret |
|---|---|---|---|---|---|
| `LUMU_DEFENDER_API_KEY` | Lumu Defender API key | string | — | ✅ yes | ✅ yes |
| `LUMU_API_BASE_URL` | Base URL of the Lumu Defender REST API | string | `https://defender.lumu.io/api` | no | no |
| `LUMU_REQUEST_TIMEOUT` | Per-request HTTP timeout (seconds) | float > 0 | `30` | no | no |
| `LUMU_NAME` | Server name reported to clients | string | `lumu-mcp-server` | no | no |
| `LUMU_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` | enum | `INFO` | no | no |
| `LUMU_DEBUG` | Enable SDK debug mode | bool | `false` | no | no |
| `LUMU_TRANSPORT` | `stdio` / `streamable-http` / `sse` | enum | `stdio` | no | no |

> The `LUMU_TRANSPORT`/`LUMU_HOST`/`LUMU_PORT`/… transport variables apply only
> to the advanced HTTP transports. The default, and the only mode used by Claude
> Desktop, is `stdio`. See [`.env.example`](.env.example) for the full list.

For local development you may place these in a git-ignored `.env` file (see
`.env.example`); in production, set them in the client's `env` block instead.

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
- _"Show me the event groupings for incident [UUID]"_
- _"Get the raw events for grouping [ID] in incident [UUID]"_

### 📝 Incident Management

- _"Add a comment to incident [UUID]: 'Investigating with network team'"_
- _"Mark incident [UUID] as read"_
- _"Begin work on incident [UUID] and assign it to user 42"_
- _"Mute incident [UUID] with comment 'False positive'"_
- _"Close incident [UUID] with comment 'Threat resolved'"_

### 🔬 Event Drill-down

- _"List the event groupings for incident [UUID]"_
- _"Show me the raw security events for grouping [ID]"_

### 🏷️ Labels

- _"List all labels"_
- _"What is label 7?"_

### 📊 Real-time Monitoring

- _"Get incident updates"_
- _"Check for recent incident activity"_

### 🔄 Advanced Workflows

- _"Get all open Malware incidents, then show details for the most recent one"_
- _"Find critical incidents that are still open and summarize their impact"_
- _"List all muted C2C incidents and help me decide which to unmute"_
- _"Show an incident's event groupings, then drill into the raw events"_

## Available Tools

### 1. `health_check`

Returns the server status. (The server requires a valid API key to start, so if
it is running the key is configured.)

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

### 4. `get_incident_events_groupings`

Retrieve the event groupings of a specific incident (bundles of raw security events). Use the returned grouping IDs with `get_security_event_details`.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `status` (optional): Array of statuses ["open", "muted", "closed"]
- `page` (optional): Page number for pagination (0-indexed, default: 0)
- `limit` (optional): Items per page (default: 50, max: 100)

**Returns**: Event grouping IDs with status and event counts.

### 5. `get_security_event_details`

Retrieve the raw data of a specific event group within an incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `event_id` (required): The event-grouping ID from `get_incident_events_groupings`
- `sort` (optional): Sort order "asc" or "desc" (default: asc)
- `page` (optional): Page number for pagination (0-indexed, default: 0)
- `limit` (optional): Items per page (default: 50, max: 100)

**Returns**: Raw security events for the event group.

### 6. `comment_incident`

Add a comment to a specific security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `comment` (required): The comment text to add

**Returns**: Confirmation of the comment being added.

### 7. `get_open_incidents`

Retrieve only open security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of open incidents with filtering options.

### 8. `get_muted_incidents`

Retrieve only muted security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of muted incidents with filtering options.

### 9. `get_closed_incidents`

Retrieve only closed security incidents.

**Parameters**:

- `adversary_types` (optional): Array of types ["C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"]
- `labels` (optional): Array of label IDs

**Returns**: List of closed incidents with filtering options.

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

Get real-time updates on incident operations (long-poll).

**Parameters**:

- `offset` (optional): Starting offset for pagination (default: 0)
- `items` (optional): Number of items to return, 1-100 (default: 50)
- `time` (optional): Maximum seconds the server waits for updates (default: 5)

**Returns**: List of incident updates with timestamps in UTC (RFC 3339/ISO 8601 format).

### 14. `close_incident`

Close a security incident.

**Parameters**:

- `incident_id` (required): The UUID of the incident to close
- `comment` (optional): Comment explaining why the incident was closed

**Returns**: Confirmation that the incident was closed.

### 15. `begin_work`

Begin work on a security incident and assign it to a user.

**Parameters**:

- `incident_id` (required): The UUID of the incident
- `assignee` (required): The numeric user ID to assign the incident to
- `comment` (optional): Comment

**Returns**: Confirmation that work has begun and the incident is assigned.

### 16. `list_labels`

List labels configured in the Lumu account (label IDs are used by the incident `labels` filters).

**Parameters**:

- `page` (optional): Page number for pagination (0-indexed, default: 0)
- `limit` (optional): Items per page (default: 50, max: 100)

**Returns**: List of labels with id, name, and relevance.

### 17. `get_label`

Get a specific label by ID.

**Parameters**:

- `label_id` (required): The numeric ID of the label

**Returns**: The label's name and relevance.

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

### Project Layout

```
lumu_mcp_server/
  config.py            # typed, env-driven settings (the only module reading env)
  server.py            # build_server(settings) -> MCPServer (composition root)
  __main__.py          # entrypoint: load settings -> build -> run
  context.py           # AppContext + get_client(ctx) for dependency injection
  services/
    lumu_client.py     # LumuDefenderClient (async HTTP client)
  tools/
    health.py          # health_check
    incidents.py       # incident query/listing tools
    actions.py         # incident mutation tools (incl. begin_work)
    administration.py  # labels
```

### Adding New Features

1. **API Methods**: Add a coroutine to `lumu_mcp_server/services/lumu_client.py`.
2. **Tool**: Add an `@mcp.tool()` function in the relevant `tools/*` module; the
   SDK generates the input schema from the function signature and docstring.
3. **Config**: Add any new setting (with a docstring + default) to `config.py`.

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
