=== MCP Abilities - Google Workspace ===
Contributors: devenia
Tags: mcp, google-workspace, gmail, ai, automation
Requires at least: 6.9
Tested up to: 6.9
Stable tag: 2.0.5
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Gmail API integration for Google Workspace via MCP.

== Description ==

This add-on plugin provides Gmail API integration through MCP (Model Context Protocol) for Google Workspace accounts. Your AI assistant can send emails, read inbox messages, reply to threads, and manage labels.
Personal Gmail accounts are not supported; you need Google Workspace with domain-wide delegation.

Part of the MCP Expose Abilities ecosystem.

== Installation ==

1. Install the required plugins (Abilities API, MCP Adapter)
2. Download the latest release
3. Upload via WordPress Admin → Plugins → Add New → Upload Plugin
4. Activate the plugin
5. Configure Google Workspace Gmail API credentials

== Changelog ==

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
