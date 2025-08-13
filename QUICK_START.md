# 🚀 Quick Start for Users

## Install in 2 Steps

### 1️⃣ Install the Package

```bash
pip install lumu-mcp-server
```

### 2️⃣ Add to Claude Desktop Config

Add this to your `claude_desktop_config.json` file:

**🍎 macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**🪟 Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**🐧 Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "lumu-mcp-server": {
      "command": "lumu-mcp-server",
      "env": {
        "LUMU_DEFENDER_API_KEY": "your-lumu-api-key"
      }
    }
  }
}
```

### 3️⃣ Restart Claude Desktop

- Quit Claude Desktop completely
- Reopen Claude Desktop
- Look for the 🔌 icon to verify connection

## ✅ Test It Works

Ask Claude:

```
"Check the health of the lumu-mcp-server"
```

or

```
"Get security incidents from Lumu Defender"
```

## 🔑 Get Your API Key

1. Log in to [Lumu Defender](https://portal.lumu.io)
2. Go to Settings → API Keys
3. Generate or copy your API key
4. Replace `your-lumu-api-key` in the config above

## 🆘 Need Help?

- 📖 [Full Documentation](README.md)
- 🐛 [Report Issues](https://github.com/jpyoda/lumu-mcp/issues)
- 💬 [Ask Questions](https://github.com/jpyoda/lumu-mcp/discussions)
