# VirusTotal

Investigate a downloaded file before running it, a suspicious link, or an IP from
a log using VirusTotal reports. The plugin connects to the authenticated
VirusTotal MCP server and includes a threat-intelligence skill. Reports provide
analysis dates and detection coverage. Missing reports and zero detections do
not establish safety.

## Install in Claude Code

<!-- client-contract:claude-code:start -->
```sh
claude plugin marketplace add VirusTotal/virustotal-mcp
claude plugin install virustotal@virustotal
```

Requires Claude Code **2.1.283 or later**. The plugin needs no separate Node.js installation and runs no hooks or bundled scripts. The plugin includes `https://ai.virustotal.com/mcp`.
<!-- client-contract:claude-code:end -->

Start a new session or run `/reload-plugins`, then use `/mcp` to sign in to
VirusTotal in your browser. No VirusTotal API key is required. If you already
have a working VirusTotal connection, avoid creating a duplicate; see the
[migration guide](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/claude-code.md#replace-an-existing-manual-connection).

For a direct connection without the plugin's skill, use this alternative:

```sh
claude mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

## Useful first tasks

- “Check this downloaded file before I run it. Calculate its SHA-256 and look up
  its VirusTotal report. Do not execute or upload it.” Provide the local path in
  Claude Code, or the actual hash when local file access is unavailable.
- “Investigate this suspicious link using its existing report.” URL lookups
  disclose the full URL, including query parameters and fragments. Remove
  credentials and private data, or request a domain-only lookup.
- “Look up the existing VirusTotal report for this IP from my log. Show its
  analysis date and coverage.” Share only the IP and relevant redacted context.

Use `/virustotal:threat-intelligence` in Claude Code to invoke the skill directly.
In Claude web chat, connect the remote server from the plugin's Connectors tab.
Local hashing depends on the host's file access and permissions. The plugin
does not execute samples, intercept execution or grant filesystem permissions.

## File submission and sharing

The remote connector cannot read local paths. This plugin includes no hooks,
scripts, automatic permission approvals or local file transfer mechanism.
Version 0.1.6 removes the upload hook from earlier releases; `file:<path>` is no
longer expanded and must not be sent to a remote submission tool. Native Claude
attachment transfer is not provided by this plugin.

When explicitly requested, `submit_attachment` can submit a file from a public
HTTPS download link. The server downloads the original bytes, computes SHA-256
and checks for an existing report before uploading. The download limit is
24,000,000 bytes. These standard submissions are shared with the VirusTotal
community and security partners, like other standard submissions.
Do not supply links containing credentials or private data.

For a local file, look up its hash first. If a submission was explicitly
requested and the report is confirmed missing, the skill can direct the user to
the [VirusTotal web uploader](https://www.virustotal.com/gui/home/upload), then
query that same hash. A web upload creates no VTAI submission receipt.

Submit files or request URL, domain or IP analyses only when explicitly asked.
Ask before sharing the user's own documents, internal code, credentials or
personal data. Submit only material the user has the right and permission to
share. Host permissions remain in force.

## Quota and recovery

Every explicit report or analysis query consumes quota, including repeats and
missing reports. New-file contributions and owned receipt recovery use no
report-query quota; returning a known file's report uses one query. Separate
contribution limits apply.

Keep the file's SHA-256 or network request ID and use `get_submission` on the
same connection to recover an uncertain outcome. Do not repeat an uncertain
submission. Respect returned polling and retry delays. Disabling the plugin
does not remove submissions from VirusTotal.

## Documentation and support

- [Setup, updates and troubleshooting](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/claude-code.md)
- [Analysis and contribution workflow](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md)
- [Privacy policy](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a security vulnerability privately](https://bughunters.google.com/)

The plugin code is licensed under Apache-2.0. VirusTotal's service terms and
data-sharing rules apply separately.
