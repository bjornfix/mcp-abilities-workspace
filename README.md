# MCP Abilities - Email

**Gmail API integration for WordPress via MCP.** Send, receive, and manage emails using Google service accounts with domain-wide delegation.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-email)](https://github.com/bjornfix/mcp-abilities-email/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

## What It Does

This add-on plugin provides full Gmail API integration through MCP (Model Context Protocol). Your AI assistant can send emails, read inbox messages, search emails, and manage labels - all through conversation.

**Part of the [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/) ecosystem.**

## Requirements

- WordPress 6.9+
- PHP 8.0+
- [Abilities API](https://github.com/WordPress/abilities-api) plugin
- [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin
- Google Workspace with service account (domain-wide delegation)

## Installation

1. Install the required plugins (Abilities API, MCP Adapter)
2. Download the latest release from [Releases](https://github.com/bjornfix/mcp-abilities-email/releases)
3. Upload via WordPress Admin → Plugins → Add New → Upload Plugin
4. Activate the plugin
5. Configure Gmail API credentials (see Setup below)

## Setup

### 1. Create Google Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project or select existing
3. Enable Gmail API
4. Create service account with domain-wide delegation
5. Download JSON key file

### 2. Configure Domain-Wide Delegation

In Google Workspace Admin:
1. Go to Security → API controls → Domain-wide delegation
2. Add the service account client ID
3. Add scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.send`
   - `https://www.googleapis.com/auth/gmail.modify`

### 3. Configure Plugin

Use `email/configure` ability to set up credentials.

## Abilities (5)

| Ability | Description |
|---------|-------------|
| `email/configure` | Set up Gmail API credentials |
| `email/send` | Send email with HTML, attachments, CC, BCC |
| `email/list` | List inbox messages with filtering |
| `email/get` | Get full email content by ID |
| `email/search` | Search emails with Gmail query syntax |

## Usage Examples

### Send email

```json
{
  "ability_name": "email/send",
  "parameters": {
    "to": "recipient@example.com",
    "subject": "Meeting Tomorrow",
    "body": "<p>Hi,</p><p>Just confirming our meeting tomorrow at 2 PM.</p>",
    "html": true
  }
}
```

### List recent emails

```json
{
  "ability_name": "email/list",
  "parameters": {
    "max_results": 10,
    "label": "INBOX"
  }
}
```

### Search emails

```json
{
  "ability_name": "email/search",
  "parameters": {
    "query": "from:important@client.com after:2024/01/01"
  }
}
```

## Security

- Uses Google service accounts (no user passwords stored)
- Domain-wide delegation controlled by Workspace admin
- Scopes limited to email operations only
- All operations logged

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Links

- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/)
- [Core Plugin (MCP Expose Abilities)](https://github.com/bjornfix/mcp-expose-abilities)
- [All Add-on Plugins](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
