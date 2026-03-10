=== MCP Abilities - Google Workspace ===
Contributors: devenia
Tags: mcp, google-workspace, gmail, ai, automation
Requires at least: 6.9
Tested up to: 6.9
Stable tag: 2.0.6
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Gmail API integration for Google Workspace via MCP.

== Description ==

This add-on plugin provides Gmail API integration through MCP (Model Context Protocol) for Google Workspace accounts. Your AI assistant can send emails, read inbox messages, reply to threads, and manage labels.
Personal Gmail accounts are not supported; you need Google Workspace with domain-wide delegation.

Part of the [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/) ecosystem.

= Requirements =

* [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities) (core plugin)
* Google Workspace with service account and domain-wide delegation
* Personal Gmail accounts are not supported

= Abilities Included =

**gmail/configure / gmail/status** - Configure and verify Gmail API access.

**gmail/list / gmail/get / gmail/list-threads / gmail/get-thread** - Read mailbox and thread content.

**gmail/send / gmail/reply** - Send new mail and reply inside existing threads.

**gmail/modify / gmail/list-labels / gmail/create-label / gmail/update-label / gmail/delete-label** - Manage labels and archive/read state.

**gmail/get-attachment / email/send** - Fetch Gmail attachments or fall back to WordPress mail when needed.

= Use Cases =

* Triage a shared support inbox through MCP
* Reply to invoice or refund emails inside the correct Gmail thread
* Label and archive handled messages automatically
* Read recent unread messages before drafting a response
* Manage Google Workspace mailboxes without opening Gmail

= Setup =

1. Create a Google Cloud project and enable the Gmail API
2. Create a service account with domain-wide delegation
3. In Google Workspace Admin, authorize the service account for Gmail scopes
4. Use `gmail/configure` to store the raw service account JSON and impersonation email

== Installation ==

1. Install the required plugins (Abilities API, MCP Adapter, MCP Expose Abilities)
2. Download the latest release
3. Upload via WordPress Admin → Plugins → Add New → Upload Plugin
4. Activate the plugin
5. Configure Google Workspace Gmail API credentials

= Links =

* [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/)
* [Core Plugin (MCP Expose Abilities)](https://github.com/bjornfix/mcp-expose-abilities)
* [All Add-on Plugins](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)

== Changelog ==

= 2.0.6 =
* Docs: expanded the WordPress-standard `readme.txt` so the published ZIP now includes fuller requirements, setup guidance, use cases, and Devenia ecosystem links

= 2.0.5 =
* Security: gmail/configure now accepts raw JSON only (no file path reads)
* Docs: sync stable tag and parameter examples with current behavior

= 2.0.4 =
* Fixed: Removed hard plugin header dependency on abilities-api to avoid slug-mismatch activation blocking


= 2.0.3 =
* Cache config access and tighten API response handling

= 2.0.2 =
* Reduce readme tags to 5 for plugin check compliance

= 2.0.1 =
* Rename plugin to Google Workspace (repo + folder + docs)

= 2.0.0 =
* Clarify Google Workspace-only support (service accounts, domain-wide delegation)

= 1.0.0 =
* Initial release
