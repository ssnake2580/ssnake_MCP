# Client configuration fragments

For automatic setup on Linux, macOS or Windows, choose your system in the [setup guide](https://ai.virustotal.com/connect/mcp). Manual shell examples below use POSIX syntax. Native package tests cover file handling and MCP protocol behavior; historical client/model validation keeps its original platform and version scope.

These fragments configure vt-mcp 0.9.2 and the compatible VTAI service: ten common tools, plus local stdio `submit_local_file` for eleven. Common tools are the four report lookups, `get_analysis`, `get_submission`, `submit_file`, `submit_url`, `reanalyze_domain` and `reanalyze_ip`. Remote HTTP never exposes the local-path tool. Choose **stdio or HTTP** for a client, merge the selected entry into its existing configuration, and preserve unrelated servers. Do not replace an entire settings file with a fragment.

Source archives include consumer configuration examples, including Cursor, VS Code, Copilot CLI and Cascade. Published archives retain their release-time recipes; use the current source for updated permission examples. The wheel does not install fragments as client settings. Check [client validation levels](../../docs/clients.md) before choosing a setup; packaging a recipe does not extend its validation.

Install the current Apache-2.0 distribution using the [README](../../README.md#install-for-local-stdio). The [historical v0.8.0 directory](https://github.com/king-tero/vt-mcp/tree/v0.8.0/examples/client-configs) retains its original MIT archive and earlier examples. The [corporate source repository](https://github.com/VirusTotal/virustotal-mcp) is public; the PyPI source archive also provides these consumer files. See [discovery status](../../docs/discovery.md).

| File | Client / destination | Historical v0.7.0 configuration evidence |
|---|---|---|
| [stdio.json](stdio.json) | Antigravity CLI (`agy`) `~/.gemini/config/mcp_config.json`; Claude Code project `.mcp.json` or file passed to `--mcp-config` | All five tools validated separately in agy 1.1.27 and Claude Code 2.1.263 |
| [claude-http.json](claude-http.json) | Claude Code project `.mcp.json` | Header expansion and all five tools validated in production with 2.1.263 |
| [codex-stdio.toml](codex-stdio.toml) | Codex `~/.codex/config.toml` | All five tools validated with CLI 0.153.4 and the public v0.7.0 wheel |
| [codex-http.toml](codex-http.toml) | Codex `~/.codex/config.toml` | `env_http_headers` and all five tools validated at the public production endpoint |
| [stdio.json](stdio.json) | Gemini/Qwen `settings.json`; Antigravity IDE's **View raw config**; Kimi `~/.kimi/mcp.json` | Shared field layout; Antigravity IDE stdio report workflow validated separately; Qwen/Kimi binaries untested |
| [gemini-qwen-http.json](gemini-qwen-http.json) | Gemini `~/.gemini/settings.json`; Qwen `~/.qwen/settings.json` | Gemini 0.38.1 resolver checked; Qwen source inspected; HTTP calls pending |
| [opencode-v1-stdio.json](opencode-v1-stdio.json) | OpenCode V1 `~/.config/opencode/opencode.json` | Public schema checked; client binary untested |
| [opencode-v1-http.json](opencode-v1-http.json) | OpenCode V1 `~/.config/opencode/opencode.json` | Public schema checked; client binary untested |

Additional recipes reviewed on 2026-09-12, with their own evidence:

| File | Client / destination | Validation scope |
|---|---|---|
| [cursor-http.json](cursor-http.json) | Cursor `~/.cursor/mcp.json` or project `.cursor/mcp.json` | CLI header expansion and discovery verified locally; IDE, tool calls and model/VTAI workflow pending |
| [vscode-http.json](vscode-http.json) | VS Code `.vscode/mcp.json` or **MCP: Open User Configuration** | Native HTTP calls and restart verified locally; [scope and model/VTAI limits](../../docs/clients.md#additional-client-validation) |
| [copilot-cli-stdio.json](copilot-cli-stdio.json) | Copilot CLI `~/.copilot/mcp-config.json` | CLI 1.0.83 completed a domain lookup with a model through public vt-mcp 0.8.0 and VTAI; other tool workflows unverified |
| [stdio.json](stdio.json) | Devin CLI v3000.3 / Local 3.6 onward, `~/.config/devin/mcp_config.json` | CLI 3000.10.21 initialized the wrapper through ACP/stdio; this configuration file, tool discovery and model/VTAI workflow remain unverified |
| [cascade-http.json](cascade-http.json) | Cascade → **MCP Servers** → raw configuration file | Open the path selected by your app version; token-file expansion, transport and native workflow pending |

Native OAuth distribution added on 2026-09-23:

| File | Client / destination | Validation scope |
|---|---|---|
| [antigravity-oauth.json](antigravity-oauth.json) | Antigravity MCP manager's raw configuration | Official `serverUrl` recipe; native OAuth and tool calls unverified |
| [gemini-extension.json](../../gemini-extension.json) | Install through `gemini extensions install` | CLI 0.58.0 native extension installation/loading checked in isolation; OAuth and tool calls unverified |

Both use browser OAuth without static credential headers. Follow the
[Google client guide](../../docs/google-clients.md) for installation, consent,
updates, revocation and account requirements.

The [setup guide](../../docs/clients.md#cursor) explains restart, discovery and
removal. Do not copy VS Code's `servers`/`inputs` format into Copilot CLI's
`mcpServers` file. Devin Local and Cascade also have separate recipes.

Cascade's documented legacy path is `~/.codeium/windsurf/mcp_config.json`; Devin
Desktop 3.10.23 on Linux opened `~/.config/devin/mcp_config.json`. Use its **MCP
Servers** action to open the correct file for your version, merge the fragment
and refresh. Preserve existing settings and avoid adding the server twice.

For stdio, install the verified wheel first. `vt-mcp` must be on the PATH used by the host; otherwise replace it with the absolute path reported by `command -v vt-mcp`. The token path is an example. vt-mcp expands `~` itself; no shell expansion of arbitrary JSON values is assumed. Declare `VTAI_TOKEN_FILE` explicitly, especially in Gemini, which filters sensitive inherited environment names. Gemini CLI no longer serves Code Assist individual, Google AI Pro or Ultra accounts through Google login; use [Antigravity CLI (`agy`)](../../docs/clients.md#antigravity-cli-agy) for those accounts.

For HTTP, no vt-mcp or Python installation is required. The earlier HTTP fragments use **`x-apikey`**; Cursor, VS Code and Cascade recipes use **`Authorization: Bearer`**. VTAI 0.8.1 accepts either with the same VTAI token; use only one header. Credential references are interpreted by each host: an environment variable for Cursor, a password input for VS Code's Extension Host, and a protected file for Cascade. This is static token authentication, not OAuth. Never replace a reference in these files with the credential itself. Load environment variables outside chat using the [access guide](../../docs/access.md#remote-client-environment). The [client guide](../../docs/clients.md#bearer-authentication-validation) documents the Bearer alternatives for earlier clients.

With v0.7.0, Antigravity CLI (`agy`), Claude Code and Codex completed the five tools at the transport levels above. See the [native-client evidence](../../docs/client-validation-2026-09-07.md) for the same selected analysis, agy's auxiliary output-file read and protocol limits. This does not validate other hosts or a different installed artifact. For an authorized test deployment, replace the URL with that deployment's exact `/mcp` URL and prefix. The REST base ending `/api/v3` is not the MCP endpoint.

OpenCode has separate [V1](https://opencode.ai/docs/mcp-servers/) and [V2](https://opencode.ai/v2/docs/mcp-servers) layouts. On 2026-09-06, the [public schema](https://opencode.ai/config.json) accepted V1 `mcp.<name>` but rejected the documented V2 `mcp.servers.<name>`. These fragments target V1 only. Pin and test a V2 binary before translating them; changing the name of this file does not establish V2 support.

No static-header HTTP fragment is provided for Antigravity or Kimi. agy 1.1.27 sent `$VAR`, `${VAR}` and `${env:VAR}` header references literally in a local discovery test. Safe header expansion remains unestablished for the reviewed Antigravity IDE and Kimi versions. Use the shared stdio fragment or the separately documented Antigravity OAuth recipe, which contains no header credential reference. No bridge package or provider-specific MCP server is needed.

## Specific permissions for autonomous tasks

[agy-permissions.json](agy-permissions.json) lists the eleven current local tools, including optional file and network writes. Merge
only its `permissions.allow` entries into
`~/.gemini/antigravity-cli/settings.json`, preserving other settings and existing
deny/ask rules. Select only entries needed for your task. Omit `submit_file`,
`submit_local_file`, `submit_url`, `reanalyze_domain` and `reanalyze_ip` for a read-only setup.
The fragment contains no credential and does not authorize arbitrary file disclosure.

Claude Code uses the exact `mcp__virustotal__...` grants in the
[client guide](../../docs/clients.md#claude-code), with three optional network-write
grants; append `mcp__virustotal__submit_local_file` only for stdio. Codex uses the same server entry
and its normal host policy for the specific tool names. Do not substitute broad
permission bypasses. Host policies and native login remain separate from VTAI.
The [0.8 submission-workflow evidence](../../docs/clients.md#version-08-submission-evidence)
records the native sessions, asynchronous results and separate public SDK checks.
The historical 0.7 configuration evidence above keeps its recorded scope.
