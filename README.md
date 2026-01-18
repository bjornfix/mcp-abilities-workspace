# MCP Abilities - Google Workspace

Gmail API integration for Google Workspace via MCP.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-workspace)](https://github.com/bjornfix/mcp-abilities-workspace/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

**Tested up to:** 6.9
**Stable tag:** 2.0.1
**License:** GPLv2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

## What It Does

This add-on plugin provides Gmail API integration through MCP (Model Context Protocol) for Google Workspace accounts. Your AI assistant can send emails, read inbox messages, reply to threads, and manage labels. Personal Gmail accounts are not supported.

**Part of the [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/) ecosystem.**

## Requirements

- WordPress 6.9+
- PHP 8.0+
- [Abilities API](https://github.com/WordPress/abilities-api) plugin
- [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin
- Google Workspace with service account (domain-wide delegation). Personal Gmail accounts are not supported.

## Installation

1. Install the required plugins (Abilities API, MCP Adapter)
2. Download the latest release from [Releases](https://github.com/bjornfix/mcp-abilities-workspace/releases)
3. Upload via WordPress Admin → Plugins → Add New → Upload Plugin
4. Activate the plugin
5. Configure Google Workspace Gmail API credentials (see Setup below)

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

Use `gmail/configure` ability to set up credentials.

## Abilities (8)

| Ability | Description |
|---------|-------------|
| `gmail/configure` | Set up Gmail API service account credentials |
| `gmail/status` | Check API connection status and configuration |
| `gmail/list` | List inbox messages with filtering |
| `gmail/get` | Get full email content by ID |
| `gmail/send` | Send email with HTML, attachments, CC, BCC |
| `gmail/modify` | Modify labels (archive, mark read/unread, etc.) |
| `gmail/reply` | Reply to an existing email thread |
| `email/send` | Send email via WordPress wp_mail (non-Gmail fallback) |

## Usage Examples

### Configure Gmail API (Google Workspace)

```json
{
  "ability_name": "gmail/configure",
  "parameters": {
    "service_account": { "...service account JSON..." },
    "impersonate_email": "user@yourdomain.com"
  }
}
```

### Send email

```json
{
  "ability_name": "gmail/send",
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
  "ability_name": "gmail/list",
  "parameters": {
    "max_results": 10,
    "label": "INBOX"
  }
}
```

### Reply to thread

```json
{
  "ability_name": "gmail/reply",
  "parameters": {
    "thread_id": "abc123",
    "body": "Thanks for the update!"
  }
}
```

### Archive email

```json
{
  "ability_name": "gmail/modify",
  "parameters": {
    "id": "message123",
    "remove_labels": ["INBOX"]
  }
}
```

## Security

- Uses Google service accounts (no user passwords stored)
- Domain-wide delegation controlled by Workspace admin
- Scopes limited to Gmail API operations only
- All operations require WordPress authentication

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Links

- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/)
- [Core Plugin (MCP Expose Abilities)](https://github.com/bjornfix/mcp-expose-abilities)
- [All Add-on Plugins](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
