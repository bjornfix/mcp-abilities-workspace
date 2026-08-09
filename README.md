# MCP Abilities - Google Workspace

Google Workspace Gmail API abilities for MCP. Service account only, inbox management, send/receive emails.

[![Release 2.0.7](https://img.shields.io/badge/release-2.0.7-blue.svg)](https://downloads.devenia.com/mcp-abilities-workspace.zip)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![WordPress](https://img.shields.io/badge/WordPress-6.9%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net)

**Tested up to:** 7.0
**Stable tag:** 2.0.7
**License:** GPLv2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

## What It Does

Google Workspace Gmail API abilities for MCP. Service account only, inbox management, send/receive emails.

This plugin is part of the MCP abilities ecosystem. It gives an MCP-capable agent a focused, authenticated way to work with Google Workspace work inside WordPress through MCP.

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
- [Plugin page](https://devenia.com/plugins/mcp-abilities-workspace/)
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

## Reader Workflows

- Configuration and status (2): configure a Google service account with domain-wide delegation for one impersonated Workspace mailbox, then check whether the connection is configured and connected.
- Label administration (5): list and inspect system or user labels, then create, update, or delete one exact label.
- Message and thread reading (5): search and page through messages or threads, inspect one exact message or thread, and retrieve one exact attachment with a configurable response limit from 1 byte to 20 MB.
- Outbound messages (3): send a new message through the configured Gmail identity, reply to one exact existing message and thread, or send through the site's WordPress mail transport.
- Mailbox state changes (1): add or remove exact labels on one message, including shortcuts for read, unread, archive, or trash state.

## Authorization and Change Boundaries

- Every operation requires an authenticated WordPress user with `manage_options`.
- Gmail operations use only the configured Google service account and one impersonated Workspace mailbox. The requested scopes are read, send, modify, and label access.
- Configuration accepts raw service account JSON only. It rejects file paths, requires a client email and valid private key, saves the configuration, and tests authentication.
- Read operations require exact message, thread, attachment, or label identifiers where applicable. Reading one message can mark it read only when that option is explicitly requested.
- Sending requires an exact recipient, subject, and body. Gmail sending can include CC and BCC recipients. Replying requires an exact source message and body, with reply all disabled unless explicitly requested. A successful call sends immediately and does not provide a separate confirmation stage.
- Mailbox changes require one exact message. Label additions and removals are explicit. Read, unread, archive, and trash shortcuts change Gmail state immediately and do not provide a separate confirmation stage.
- Label deletion requires one exact label identifier and deletes it immediately. Label creation and updates use the supplied name, visibility, and optional color fields.

## Dependencies

The exact runtime and integration dependencies are listed in [DEPENDENCIES.md](DEPENDENCIES.md).

[Download MCP Abilities - Google Workspace](https://downloads.devenia.com/mcp-abilities-workspace.zip)

## Registered Abilities (16)

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
| `gmail/send` | Send email with HTML, CC, and BCC |
| `gmail/modify` | Modify labels (archive, mark read/unread, etc.) |
| `gmail/reply` | Reply to an existing email thread |
| `email/send` | Send email through the site's WordPress mail transport |

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
    "message_id": "abc123",
    "body": "Thanks for the update!"
  }
}
```

### Archive email

```json
{
  "ability_name": "gmail/modify",
  "parameters": {
    "message_id": "message123",
    "remove_labels": ["INBOX"]
  }
}
```

## Changelog

### 2.0.7
- Update tested WordPress version metadata for Plugin Check.
- Align public release identity with the Basicus author/contributor rule.

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

[basicus](https://profiles.wordpress.org/basicus/)

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
