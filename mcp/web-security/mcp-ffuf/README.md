# mcp-ffuf

MCP server that exposes [ffuf](https://github.com/ffuf/ffuf) (HTTP fuzzer) as tools an LLM agent can call — with **mandatory scope enforcement** and a hard cap on requests per run so an agent can't accidentally hammer a host into the ground.

Part of a small family of responsible MCP wrappers around common offensive-security tools:
[mcp-nmap](https://github.com/samcsta/mcp-nmap) ·
[mcp-ffuf](https://github.com/samcsta/mcp-ffuf) ·
[mcp-nuclei](https://github.com/samcsta/mcp-nuclei).

## Install

```bash
npm install
```

Requires Node.js ≥ 22.5 and `ffuf` on `PATH`. On macOS: `brew install ffuf`.

## Scope is mandatory

Set `MCP_FFUF_SCOPE` to a comma-separated list of authorized hostnames. Supported forms:

- **Exact hostname**: `api.example.com`
- **Wildcard hostname**: `*.example.com`

IPs are not accepted — ffuf runs against URLs, and the scope check normalizes targets to their hostname.

```bash
export MCP_FFUF_SCOPE="*.example.internal,api.example.com"
node src/index.js
```

If `MCP_FFUF_SCOPE` is unset, **every fuzz is refused.**

## Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "ffuf": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-ffuf/src/index.js"],
      "env": { "MCP_FFUF_SCOPE": "*.example.internal" }
    }
  }
}
```

## Tools

| Tool | Purpose |
|---|---|
| `fuzz_path` | Discover paths/files. URL contains `FUZZ`, e.g. `https://target/FUZZ`. Options: `wordlist`, `extensions`, `match_codes`, `filter_codes`. |
| `fuzz_parameter` | Discover GET parameters. URL contains `FUZZ`, e.g. `https://target/?FUZZ=test`. |
| `fuzz_vhost` | Discover virtual hosts via the Host header. |
| `check_scope` | Return whether a URL's host is in scope without running ffuf. |

All tools return parsed ffuf JSON output.

## Safety

- **Scope enforcement** runs before spawning ffuf. Out-of-scope targets never touch the binary.
- **Hard request cap** — every run includes `-maxtime` (default 60s) and the `-rate` flag is always bounded.
- **Wordlist paths are validated** to be absolute and existing. You cannot pass `;` / `|` / `$(...)` — arg parsing is structured.
- **Polite defaults** — `-t 10` concurrency, `-rate 20` per second, `-timeout 10`.

## Legal

Only fuzz hosts you own or have explicit written permission to test. Fuzzing traffic is indistinguishable from a brute-force attack to a defender. The scope allowlist configures what *you* believe you have authority to hit; it cannot verify that authority. That is on you.

## License

MIT — see [LICENSE](LICENSE).
