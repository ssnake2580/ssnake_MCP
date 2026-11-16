# Security

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab -> "Report a vulnerability"). Do not open a public issue for security problems.

## Threat model

gitleaks-mcp runs locally over stdio, with the permissions of the user who launches it, and is driven by an LLM. Assume the model's arguments can be wrong or influenced by untrusted content (prompt injection).

What the server does to limit that:

- **No secret output.** Scans always run with `--redact`, and the raw `Match`/`Secret` fields are discarded. Only rule, file, line, commit and fingerprint are returned.
- **No shell.** `gitleaks` is launched with `execFile` and an argument array; nothing is interpolated into a command line.
- **`log_opts` is allowlisted.** It is forwarded to `git log`, so only revisions/ranges and a few harmless flags are accepted. Flags that write files or run programs (`--output`, `--ext-diff`, `--textconv`, `--exec`, ...) are rejected.
- **Read-only tools.** No tool modifies the scanned repository. Temporary reports live in a private temp directory and are deleted after each scan.
- **No network access, no telemetry, no credentials needed.**

## Known limits - read before using

- **Only scan repositories you trust.** Running `git` inside an untrusted repository can execute code configured by that repository (for example `core.fsmonitor` in its `.git/config`). This is a property of git, not of this server.
- **Paths are not sandboxed.** The agent can point a scan at any directory your user can read. Findings are redacted, but file paths and the existence of secrets are reported. Run the server in a container or restrict the client's file permissions if that matters to you.
- A scanner finds known patterns; a clean result does not prove a repository is free of secrets.
- If a finding is real, **rotate the credential** - removing it from history is not enough.
