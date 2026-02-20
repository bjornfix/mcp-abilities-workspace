# MCP Abilities - Google Workspace

Gmail API integration for Google Workspace via MCP.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-workspace)](https://github.com/bjornfix/mcp-abilities-workspace/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

**Tested up to:** 6.9
**Stable tag:** 2.0.5
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
3. Upload via WordPress Admin > Plugins > Add New > Upload Plugin
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
1. Go to Security > API controls > Domain-wide delegation
2. Add the service account client ID
3. Add scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.send`
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/gmail.labels`

### 3. Configure Plugin

Use `gmail/configure` ability to set up credentials. The `service_account_json` parameter must be raw JSON content (not a file path).

## Abilities (16)

| Ability | Description |
|---------|-------------|
| `gmail/configure` | Set up Gmail API service account credentials |
| `gmail/status` | Check API connection status and configuration |
| `gmail/list-labels` | List Gmail labels |
| `gmail/get-label` | Get a Gmail label by ID |
| `gmail/create-label` | Create a Gmail label |
| `gmail/update-label` | Update a Gmail label |
| `gmail/delete-label` | Delete a Gmail label |
| `gmail/list` | List inbox messages with filtering |
| `gmail/list-threads` | List Gmail threads |
| `gmail/get` | Get full email content by ID |
| `gmail/get-thread` | Get a Gmail thread |
| `gmail/get-attachment` | Fetch a message attachment (base64) |
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
    "service_account_json": "{...raw service account JSON...}",
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

## Concrete Workflow Example

### Triage support inbox and send a reply draft

1. List unread support emails:

```json
{
  "ability_name": "gmail/list",
  "parameters": {
    "label": "INBOX",
    "q": "is:unread subject:(invoice OR billing OR refund)",
    "max_results": 5
  }
}
```

2. Get the full message content for the top hit:

```json
{
  "ability_name": "gmail/get",
  "parameters": {
    "id": "MESSAGE_ID_FROM_LIST"
  }
}
```

3. Reply in the same thread:

```json
{
  "ability_name": "gmail/reply",
  "parameters": {
    "thread_id": "THREAD_ID_FROM_GET",
    "body": "Hi! Thanks for contacting us. I have checked your invoice and processed the correction. You will receive the updated receipt shortly."
  }
}
```

4. Label and archive the handled message:

```json
{
  "ability_name": "gmail/modify",
  "parameters": {
    "id": "MESSAGE_ID_FROM_LIST",
    "add_labels": ["Label_1234567890"],
    "remove_labels": ["INBOX", "UNREAD"]
  }
}
```

## Security

- Uses Google service accounts (no user passwords stored)
- Domain-wide delegation controlled by Workspace admin
- Scopes limited to Gmail API operations only
- All operations require WordPress authentication

## Changelog

### 2.0.5
- Security: gmail/configure now accepts raw JSON only (no file path reads)
- Docs: sync stable tag and parameter examples with current behavior

### 2.0.4
- Fixed: Removed hard plugin header dependency on abilities-api to avoid slug-mismatch activation blocking

### 2.0.3
- Cache config access and tighten API response handling

### 2.0.2
- Reduce readme tags to 5 for plugin check compliance

### 2.0.1
- Rename plugin to Google Workspace (repo + folder + docs)

### 2.0.0
- Clarify Google Workspace-only support (service accounts, domain-wide delegation)

### 1.0.0
- Initial release

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Links

- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/)
- [Core Plugin (MCP Expose Abilities)](https://github.com/bjornfix/mcp-expose-abilities)
- [All Add-on Plugins](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
