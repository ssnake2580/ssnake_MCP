# VirusTotal for Antigravity

Investigate file hashes, URLs, domains and IP addresses with VirusTotal reports.
This plugin bundles the remote MCP connection and a `threat-intelligence` skill
for report interpretation, authorized submissions and receipt recovery.
Start with a downloaded file, a suspicious link or an IP from your logs. The
agent looks up existing reports first; it does not upload files or request a new
analysis unless you explicitly ask.

It complements the existing [Agy local stdio integration](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/clients.md#antigravity-cli-agy)
and [VT Sentinel extension for Antigravity IDE](https://open-vsx.org/extension/virustotal/vt-sentinel),
also available from [ai.virustotal.com](https://ai.virustotal.com/).
VT Sentinel provides its own editor protection workflow. This plugin supplies
tools and guidance to the agent; it does not intercept downloads or execution.

## Install from Marketplace

Requires a current Antigravity CLI and an active `agy` sign-in session. In your
terminal shell, outside an Agy conversation, run:

```sh
agy plugin install virustotal@antigravity-plugins-partners
agy plugin list
agy
```

The catalog suffix selects VirusTotal's partner listing. `agy plugin list` should
show `virustotal` enabled. If it is disabled, run `agy plugin enable virustotal`.

Already installed? Continue to [Connect and verify](#connect-and-verify).

In the Antigravity App, use **Customizations → Marketplace**, search for
**VirusTotal**, and install it. Google lists VirusTotal in the
[Marketplace launch announcement](https://antigravity.google/blog/plugin-marketplace-in-antigravity).
See Google's [Marketplace guide](https://antigravity.google/docs/marketplace)
for the CLI and App controls. Installation and VirusTotal authorization are
separate steps; continue below.

If VirusTotal is absent from your catalog, or an install command reports
**plugin not found**, use [installation from source](#install-from-source-instead).
Do not repeatedly reinstall an existing plugin to complete authorization.

If you already use a `virustotal` MCP connection, keep one active connection and
preserve other servers. Recover uncertain submissions before changing a
connection, because receipts belong to the identity that submitted them. A
working local stdio or VT Sentinel installation does not need to be replaced.

## Connect and verify

The bundled server is `https://ai.virustotal.com/mcp`. It uses the host's OAuth
flow; the plugin contains no API key, static token or Google ADC configuration.
Start a new Agy session and open `/mcp`. Select `virustotal_virustotal`, choose
**Authenticate**, and leave that terminal dialog open while you finish browser
sign-in and consent. If Google's callback page shows an authorization code:

1. Copy the code from the browser page.
2. Return to the **same terminal window running Agy**.
3. Paste it into the authentication dialog's code field and submit it there.
   The code goes in this dialog, never in the conversation or a shell command.
4. Wait for the connection result before starting another authentication attempt.
   Once connected, return to the conversation and try a task below.

While `/mcp` shows a server loading, let it finish before selecting Authenticate
again. If it reports an error, read that status before retrying; repeatedly
installing or clicking Authenticate does not finish a pending code-entry step.
In Antigravity's graphical settings, use **Customizations → Authenticate** and
paste the callback code into the settings panel's authentication field.
Follow Google's [MCP authentication guide](https://antigravity.google/docs/mcp/).

Authorize only the operations your task needs. Report access, file submission
and network analysis have separate VTAI permissions. The host's tool permission
settings still apply; this plugin adds no blanket approval rule. A model login
does not grant access to VTAI. If the host cannot complete OAuth, use the existing
[Agy stdio setup](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/clients.md#antigravity-cli-agy).

## Try your first task

Paste one of these requests into the Agy conversation. In the App, the plugin's
detail page also provides suggested prompts.

- **Downloaded file:** “Check a file I downloaded before I run it. Ask me for its
  local path, compute SHA-256 without executing it, and look up its existing
  VirusTotal report. Do not upload it.”
- **Suspicious link:** “Help me assess a suspicious link. Explain what a URL
  lookup shares before asking for it, then retrieve its existing VirusTotal
  report. Do not open the link or submit it for analysis.”
- **IP from a log:** “Investigate an IP address from my logs. Ask for the IP and
  a brief description of the activity, retrieve its existing VirusTotal report,
  and explain the evidence and its limits. Do not request a new analysis.”

For a file, the agent uses a local tool to compute its hash; the remote server
receives the hash for the lookup, not the file bytes. If the agent cannot read
the file locally, provide its hash instead. For a URL, the complete URL is
shared with VTAI and VirusTotal; use a domain lookup when sufficient and avoid
links containing secrets or personal data.

Inspect the actual tool result. Installation, validation and a connected status
alone do not prove a successful query. Missing reports mean unknown; zero
detections do not establish safety. Native browser sign-in and a report query
have been verified in Agy; token renewal, write operations and the graphical
applications have separate validation requirements. See [validation status](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/google-clients.md#validation-and-discovery).

## Install from source instead

Use this alternative to review or test the repository's plugin version. Requires
Git. From a directory where you keep source checkouts:

```sh
git clone https://github.com/VirusTotal/virustotal-mcp.git
agy plugin validate ./virustotal-mcp/plugins/antigravity
agy plugin install ./virustotal-mcp/plugins/antigravity
agy plugin list
```

Review the directory before installing. Pass the `plugins/antigravity`
subdirectory, not the repository root. If you already have a checkout, use its
local path. See Google's [plugin guide](https://antigravity.google/docs/plugins?tab=cli).
Marketplace and source versions may differ; `agy plugin list` shows the version
and source actually installed.

## Files, sharing and costs

The remote server accepts original file bytes, not paths on your computer. This
plugin includes no local upload hook and does not expand `file:<path>`. Direct
`submit_file` use requires a host mechanism that transfers the original bytes
programmatically; do not ask the model to transcribe base64. The local stdio
integration offers `submit_local_file`. See the [file workflow](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md)
for the hash-first web-upload fallback when byte transfer is unavailable.

Standard submissions are shared with the VirusTotal community and security
partners. Submit only when the user explicitly requests it. Ask before sharing
your own documents, internal code, credentials or
personal data. Only submit material you have the right and permission to share.
Inline bytes also pass through MCP tool arguments, which the host or model
provider may retain. Removing this plugin does not withdraw submitted content.
URL queries disclose the complete URL, including query and fragment, to VTAI
and VirusTotal; use domain scope when sufficient and avoid secret URLs.

VTAI access is free subject to its quotas; Antigravity model access and credits
are separate. Every report or analysis read counts, including repeats and missing
reports. New-file contributions and owned receipt recovery use no report-query
quota; an existing file's returned report costs one query. Unknown-file
contributions have a separate allowance of 20 per fixed minute and 500 per UTC
day, shared by the signed-in VTAI account. Honor retry delays and reuse your
existing account. Never create identities to evade limits. Keep the hash or
request ID and recover uncertain submissions with `get_submission` instead of
repeating them. [Quota and recovery details](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

## Update, disable or remove

For a local installation, update your reviewed checkout and reinstall its plugin
directory with `agy plugin install` from your shell. Preserve the existing
connection until any uncertain submissions have been recovered. Manage the
installation with:

```sh
agy plugin disable virustotal
agy plugin enable virustotal
agy plugin uninstall virustotal
```

For permanent disconnection, also revoke its access in
[Your connections](https://ai.virustotal.com/oauth/connections). Disabling or
uninstalling local files alone does not revoke the grant. Do not delete or copy
the host's credential files.

## Documentation and support

- [Google client connections](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/google-clients.md)
- [Privacy notice](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a vulnerability privately](https://bughunters.google.com/)

Plugin code is licensed under [Apache-2.0](https://github.com/VirusTotal/virustotal-mcp/blob/main/LICENSE).
Service terms and sharing rules apply separately.
