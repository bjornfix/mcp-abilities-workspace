# MCP Abilities - Google Workspace

Google Workspace Gmail API abilities for MCP. Service account only, inbox management, send/receive emails.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-workspace)](https://github.com/bjornfix/mcp-abilities-workspace/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![WordPress](https://img.shields.io/badge/WordPress-6.9%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net)

**Tested up to:** 7.0
**Stable tag:** 2.0.6
**License:** GPLv2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

## What It Does

Google Workspace Gmail API abilities for MCP. Service account only, inbox management, send/receive emails.

This plugin is part of the Devenia MCP abilities ecosystem. It gives an MCP-capable agent a focused, authenticated way to work with Google Workspace work inside WordPress through MCP.

**Example:** "Handle this WordPress maintenance task directly." - The agent can inspect the site, call the relevant ability, and return the result without making the human click through wp-admin for every step.

## The Real Workflow

In practice, the human should not have to memorize every ability name.

The normal pattern is:

1. install the base MCP stack
2. install only the add-ons the site actually needs
3. let the agent discover the available abilities
4. give the agent a clear task with boundaries
5. verify the result in WordPress

The human's job is mostly to describe the goal.
The agent's job is to figure out the mechanics.

## Why This Feels Different

Most WordPress automation still leaves the repetitive part to the human.

This plugin is different because the agent can act inside the site through a narrow, authenticated ability surface:

- inspect current site state before changing anything
- run the specific action needed for the task
- return structured results that are easy to verify
- keep the workflow inside WordPress instead of a separate checklist

That changes the experience from:

- `Here is what you should do in wp-admin`

to:

- `Tell the agent what needs doing, and let it carry out the work`

## Before vs After

### Before

- ask the AI what to do
- copy the answer into WordPress by hand
- click through wp-admin for the repetitive bits
- postpone maintenance because the task is tedious

### After

- tell the agent what needs doing
- let it inspect the relevant WordPress state
- let it run the targeted ability
- verify the result and move on

## Who It Is For

This is a good fit for:

- agencies managing WordPress sites with AI-assisted maintenance
- operators who want agents to do real WordPress work instead of producing instructions
- teams already using MCP Expose Abilities
- sites where this WordPress area is updated often enough to deserve automation

It is especially useful when the manual version is repetitive enough that important maintenance gets delayed.

## Documentation

Start with the main plugin page and base stack documentation:

- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
- [Getting Started](https://github.com/bjornfix/mcp-expose-abilities/wiki/Getting-Started)
- [Install Order and Dependencies](https://github.com/bjornfix/mcp-expose-abilities/wiki/Install-Order-and-Dependencies)

If you are using an AI agent, the simplest instruction is often just:

- `Read https://github.com/bjornfix/mcp-expose-abilities and figure out the stack before making changes.`

## Start Here

If you are new to the stack, use this order:

1. Install **Abilities API**.
2. Install **MCP Adapter**.
3. Install **MCP Expose Abilities**.
4. Install **MCP Abilities - Google Workspace**.
5. Confirm the new abilities appear in discovery.
6. Give the agent a clear task that uses this add-on.

If you skip base-stack verification and start with add-ons immediately, troubleshooting gets harder than it needs to be.

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

## Changelog

### 2.0.6
- Docs: expanded the WordPress-standard `readme.txt` so the published ZIP now includes fuller requirements, setup guidance, use cases, and Devenia ecosystem links

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

## Contributing

PRs welcome. Keep changes focused on the plugin's WordPress ability surface and preserve authenticated, explicit workflows.

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Links

- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [GitHub Releases](https://github.com/bjornfix/mcp-abilities-workspace/releases)

## Star and Share

If this plugin saves you time or makes WordPress maintenance easier to verify, please:

- star the repo
- share it with people running WordPress sites
- point them to the main plugin page so they can see what the ecosystem can actually do

Why do it?

Because agent-friendly open WordPress tooling helps more of the boring but important work get done.
