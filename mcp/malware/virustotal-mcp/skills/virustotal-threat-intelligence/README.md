# VirusTotal threat-intelligence skill

Portable instructions for an already connected VirusTotal MCP app. The skill
contains no scripts, credentials or server configuration. It does not install
or authenticate the connection and does not grant submission permissions.

For Gemini Apps, follow the [connection and import guide](../../docs/google-clients.md#gemini-apps-skill).
Download the plain-text [SKILL.md](https://github.com/VirusTotal/virustotal-mcp/releases/download/gemini-skill-v0.1.0/SKILL.md),
keep its filename and use **Settings → Skills → Upload**. Select `SKILL.md`,
review the instructions and choose **Create**. If you already downloaded the
[skill ZIP](https://github.com/VirusTotal/virustotal-mcp/releases/tag/gemini-skill-v0.1.0),
extract its single `SKILL.md` and select that file. Some upload dialogs accept
only `SKILL.md`; ZIP acceptance is not guaranteed. Checksums are on the release.
The repository's full source ZIP is not a skill archive. You can import the
instructions separately, but live reports require the connected MCP app.
Eligibility and hosted validation limits are recorded in the guide.

The [Gemini CLI extension](../../docs/google-clients.md#gemini-cli-extension)
bundles this directory. Other skill-compatible hosts can reuse `SKILL.md` with
their connected MCP tools; format compatibility does not prove a tested workflow
in every host. Existing Antigravity installations retain their plugin's own skill.

Example after connection:

> Use VirusTotal to retrieve the existing report for example.com. Explain the
> source, analysis date, coverage and limitations. Do not request a new analysis.

Deleting or deactivating a skill does not revoke the MCP connection. Update or
replace imports explicitly after reviewing new instructions.
