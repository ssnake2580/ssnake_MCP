# VirusTotal for Claude Code

The VirusTotal plugin provides the OAuth MCP connection and a skill for
investigating file hashes, suspicious links, domains and IP addresses.
Version 0.1.6 contains no hooks or bundled scripts and does not transfer local
files. Claude can hash an authorized local file without executing it, then
query its existing report. Missing reports and zero detections do not establish
safety.

## Install and connect

<!-- client-contract:claude-code:start -->
```sh
claude plugin marketplace add VirusTotal/virustotal-mcp
claude plugin install virustotal@virustotal
```

Requires Claude Code **2.1.283 or later**. The plugin needs no separate Node.js installation and runs no hooks or bundled scripts. The plugin includes `https://ai.virustotal.com/mcp`.
<!-- client-contract:claude-code:end -->

Start a new session or run `/reload-plugins`, then `/mcp` to authenticate in your
browser. No Python, separate Node.js, VirusTotal API key or copied OAuth token is
needed. The plugin already supplies the MCP connection; avoid adding a duplicate.
The skill is available as `/virustotal:threat-intelligence`.

Try checking a downloaded file by hash before running it, investigating a
suspicious link, or looking up an IP from a redacted log. Use existing reports
for these tasks; request a submission or reanalysis explicitly when intended.
URL lookups disclose the full URL, including query parameters and fragments,
to VTAI and VirusTotal. Do not send URLs with credentials or private data; use a
domain lookup when sufficient.

### Updating from 0.1.5 or earlier

Update the marketplace and installed plugin:

```sh
claude plugin marketplace update virustotal
claude plugin update virustotal@virustotal
```

Start a new session or run `/reload-plugins`. The previous upload hook and its
Node.js requirement are removed. `VTAI_UPLOAD_ROOTS` no longer configures this
plugin, and `file:<path>` is not expanded. Existing host permissions control
local hashing. Do not copy the retired hook into your configuration.

### Manual HTTP alternative without Node.js

For the same remote connection without the skill:

```sh
claude mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

Open `/mcp` and complete browser sign-in. Choose either this connection or the
plugin, avoiding duplicate server entries.

## Files and sharing

The remote connector cannot read local paths. Obtain the file's actual SHA-256
using an available hashing tool within the user's authorized file scope, or ask
for the hash when local access is unavailable. Do not execute the sample or
transcribe base64. Call `get_file_report` with the hash. A missing report does
not authorize uploading or executing the file.

For an explicitly requested submission, `submit_attachment` accepts a public
HTTPS download link. The server downloads up to 24,000,000 original bytes,
computes SHA-256 and checks for an existing report. Only a confirmed missing
report permits a new contribution; a known file returns its existing report.
Do not use a link with credentials or private data, or publish a local file to
create a link. This plugin does not provide native Claude attachment transfer.

For local files without a suitable download link, an explicitly requested
submission and a confirmed missing report permit directing the user to the
[VirusTotal web uploader](https://www.virustotal.com/gui/home/upload). Then query
the same hash. A web upload has no VTAI receipt. Permission, quota and service
errors do not establish absence or justify changing upload methods to bypass a
refusal.

Standard submissions are shared with the VirusTotal community and security
partners. Ask before sharing the user's own documents, internal code,
credentials or personal data; submit only material the user has the right and
permission to share. Request URL, domain and IP analyses only when explicitly
asked. Host permissions remain in force.

Every explicit report or analysis query counts toward quota, including repeats
and missing reports. New-file contributions and owned receipt recovery use no
report-query quota; returning an existing file report uses one query. Respect
contribution limits and retry delays. For uncertainty, retain the SHA-256 or
network request ID and recover with `get_submission` on the original connection;
never replay a submission to find out whether it succeeded. See
[analysis and recovery](analysis.md).

### Replace an existing manual connection

Only if you previously added a manual VirusTotal entry, identify its exact name
and scope with `claude mcp list` and `claude mcp get <name>`. Recover any uncertain
submission on its original connection before removing that entry. Remove it
from the scope in which you configured it before using the plugin connection. For
example, for an entry named `virustotal` in the current project's local scope:

```sh
claude mcp remove --scope local virustotal
```

Use `--scope user` or `--scope project` only when that is the existing entry's
scope, and substitute its actual name. If the same manual entry exists in more
than one scope, review each one instead of removing an unrelated server.
[Removing a remote server](https://code.claude.com/docs/en/mcp#managing-your-servers)
also clears its locally stored OAuth tokens and client registration, so expect
to sign in again for the plugin. Do not manually delete credentials, revoke
server grants, delete submission receipts or disconnect the personal claude.ai
connection. Fresh installations need no removal command.

## Validation and removal

The package is checked for its declared files, credential-free HTTPS MCP
configuration, UTF-8 text and absence of hooks or bundled programs. Native
`claude plugin validate` checks syntax and schema; Anthropic's directory performs
its own separate policy review. A local validation pass is not directory approval.

Earlier authenticated local-upload tests applied to releases with the retired
hook and do not describe version 0.1.6. No authenticated local upload, native
attachment transfer or Cowork file transfer is claimed for this version.

```sh
claude plugin disable virustotal@virustotal
claude plugin uninstall virustotal@virustotal
```

Disabling or removing the plugin does not erase remote submissions or receipts.
See the official [plugin installation guide](https://code.claude.com/docs/en/discover-plugins)
and [manifest reference](https://code.claude.com/docs/en/plugins-reference).
