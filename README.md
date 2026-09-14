# MCP Abilities - Google Workspace

Read a Google Workspace message, review its thread, and send an approved reply through the same Gmail mailbox from your WordPress-connected assistant.

[![Release 2.0.8](https://img.shields.io/badge/release-2.0.8-blue.svg)](https://downloads.devenia.com/mcp-abilities-workspace.zip)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![WordPress](https://img.shields.io/badge/WordPress-6.9%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net)

**Tested up to:** 7.0
**Stable tag:** 2.0.8
**License:** GPLv2 or later
**Tags:** mcp, google-workspace, gmail, ai, automation

## What It Does

The plugin registers 16 WordPress abilities: 15 for Gmail and one for the site's WordPress mail transport. Search messages, read complete threads, retrieve attachments, manage labels, and send mail from one configured Workspace identity. Search and thread lists support pagination.

Despite its name, this add-on covers Gmail. It does not provide Google Drive, Calendar, Docs, or a personal Gmail sign-in flow.

## The Real Workflow

1. Ask the assistant to find the relevant messages with Gmail search and label filters.
2. Read the selected message and its thread before preparing a reply. Reading preserves unread state unless `mark_read` is explicitly requested.
3. Review the exact reply and recipients in your assistant. `gmail/reply` sends immediately when called; the plugin has no draft approval screen.
4. Apply agreed labels or archive the handled message, then inspect the result.

For example: “Find unread messages in the support mailbox about order EX-104. Read the matching thread and draft a reply for my review.” Your assistant owns that review step; the plugin supplies the mailbox operations.

## Why This Feels Different

The reply uses the original Gmail thread ID and message references. It follows Reply-To when present. Explicit reply-all adds original To and Cc recipients while excluding the configured mailbox from the added copies. The assistant can inspect context and change the same message through named operations, without copying a conversation between separate tools.

## Before vs After

| Task | Manual hand-off | With these abilities |
|---|---|---|
| Find context | Copy messages into an assistant | Search and retrieve the selected thread |
| Reply | Paste approved text back into Gmail | Send the approved text through `gmail/reply` |
| Close the task | Return to Gmail to apply labels | Change the exact message's labels and verify them |

## Who It Is For

Teams with a Google Workspace mailbox and an authenticated WordPress MCP setup can use this for reviewed support correspondence, message research, and mailbox organisation. A Workspace administrator must authorise domain-wide delegation. It is not a personal Gmail connector or a multi-mailbox dashboard.

## Requirements

Use WordPress 6.9+, PHP 8.0+ with OpenSSL, the WordPress Abilities API, MCP Adapter, and MCP Expose Abilities. Gmail access needs an enabled Gmail API, a service account with domain-wide delegation, and one Workspace user to impersonate. The dependency list is in [DEPENDENCIES.md](DEPENDENCIES.md).

## Documentation

- [Google Workspace plugin page](https://devenia.com/plugins/mcp-abilities-workspace/)
- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [Google's domain-wide delegation guide](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority)

## Start Here

1. Install and verify the WordPress MCP stack, then activate this add-on.
2. Enable the Gmail API for a Google Cloud service account.
3. Have a Workspace super administrator authorise the service account's client ID for these scopes: `https://www.googleapis.com/auth/gmail.readonly`, `https://www.googleapis.com/auth/gmail.send`, `https://www.googleapis.com/auth/gmail.modify`, and `https://www.googleapis.com/auth/gmail.labels`.
4. Call `gmail/configure` with the raw service account JSON and the Workspace user's email address. A file path is not accepted.
5. Call `gmail/status`, then perform a narrow search to confirm the selected mailbox.

The credentials are saved in WordPress options. Treat access to the WordPress database and administrator account as access to this integration.

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

Search unread inbox messages without fetching each message's metadata:

```json
{"ability_name":"gmail/list","parameters":{"query":"is:unread","label_ids":["INBOX"],"max_results":10,"include_details":false}}
```

Read a selected message without changing its unread state:

```json
{"ability_name":"gmail/get","parameters":{"message_id":"message123","mark_read":false}}
```

After the text and recipients have been approved, send a new HTML message:

```json
{"ability_name":"gmail/send","parameters":{"to":"recipient@example.com","subject":"Your order EX-104","body":"<p>Your replacement has been arranged.</p>"}}
```

Reply to one selected message, without reply-all:

```json
{"ability_name":"gmail/reply","parameters":{"message_id":"message123","body":"<p>Thank you for confirming.</p>","reply_all":false}}
```

Archive one reviewed message by removing its Inbox label:

```json
{"ability_name":"gmail/modify","parameters":{"message_id":"message123","remove_labels":["INBOX"]}}
```

## Authorization and Change Boundaries

Every ability requires `manage_options`. Gmail calls use the configured Workspace mailbox. Sending, replying, modifying labels, trashing messages, and deleting labels take effect when called. The plugin does not add a separate confirmation step, an approval queue, or a scheduler. Set those boundaries in the assistant before granting it an action.

`gmail/get-attachment` returns base64 attachment data with an explicit response limit of up to 20 MB. It does not save the file to WordPress. `email/send` calls WordPress `wp_mail` separately; it is not an automatic retry for Gmail failures, and transport acceptance does not prove delivery.

## Installation

Download the [plugin ZIP](https://downloads.devenia.com/mcp-abilities-workspace.zip). In WordPress, open Plugins → Add New → Upload Plugin, select the ZIP, install, and activate it. Complete the Start Here steps before using Gmail abilities.

## Changelog

### 2.0.8
- Correct Gmail array query parameters, label filtering, and label list serialization.
- Report failed message detail and mark-read requests instead of claiming success.
- Preserve reply recipients and thread references; format UTF-8 mail with WordPress's MIME library.
- Reject unsafe mail headers, validate credential field types, and keep attachment data out of message text.

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

Keep changes focused on the documented abilities and include a reproducible behaviour check.

## License

GPLv2 or later.

## Author

[basicus](https://profiles.wordpress.org/basicus/)

## Links

- [Plugin page](https://devenia.com/plugins/mcp-abilities-workspace/)
- [Download](https://downloads.devenia.com/mcp-abilities-workspace.zip)
- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
