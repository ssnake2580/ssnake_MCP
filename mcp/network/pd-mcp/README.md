<div align="center">

[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![stars](https://img.shields.io/github/stars/toxicwind/pd-mcp?style=flat)](https://github.com/toxicwind/pd-mcp/stargazers)
[![bun](https://img.shields.io/badge/bun-1.4-f9f1e1?logo=bun)](https://bun.sh)
[![mcp](https://img.shields.io/badge/MCP-stdio-7c3aed)](https://modelcontextprotocol.io)
[![projectdiscovery](https://img.shields.io/badge/tools-8-00ADD8)](https://projectdiscovery.io)

# 🔭 pd-mcp

**Every ProjectDiscovery recon tool behind one MCP server your agent can call.**
subfinder · dnsx · naabu · httpx · katana · nuclei · tlsx · shuffledns — plus a
`bug_bounty_workflow` composite — over MCP stdio, with no-shell spawns, hard timeouts,
and input validation at every tool boundary.

[Report Bug](https://github.com/toxicwind/pd-mcp/issues/new?labels=bug&template=bug_report.md) · [Request Feature](https://github.com/toxicwind/pd-mcp/issues/new?labels=enhancement&template=feature_request.md)

</div>

<details>
<summary><b>Table of Contents</b></summary>
<ol>
<li><a href="#-about">About</a></li>
<li><a href="#-tools">Tools</a></li>
<li><a href="#-getting-started">Getting started</a></li>
<li><a href="#-30-second-proof">30-second proof</a></li>
<li><a href="#%EF%B8%8F-configuration">Configuration</a></li>
<li><a href="#-what-changed-from-upstream">What changed from upstream</a></li>
<li><a href="#-roadmap">Roadmap</a></li>
<li><a href="#-contributing">Contributing</a></li>
<li><a href="#-license">License</a></li>
<li><a href="#-contact">Contact</a></li>
<li><a href="#-acknowledgments">Acknowledgments</a></li>
</ol>
</details>

---

## 🔭 About

An MCP (Model Context Protocol) server that gives coding agents and chat clients direct,
structured access to [ProjectDiscovery](https://projectdiscovery.io)'s recon toolkit —
subdomain enumeration, DNS probing, port scanning, HTTP fingerprinting, crawling, vulnerability
scanning, TLS probing, and active subdomain brute-forcing — without shelling out, without
hanging the client, and without trusting agent-supplied input.

This is an **estate-hardened fork** of [`intelligent-ears/pd-tools-mcp`](https://github.com/intelligent-ears/pd-tools-mcp):
every executor goes through one timeout-guarded runner that spawns binaries directly (no shell),
resolves them from absolute paths, validates domains/hosts/ports at the tool boundary, and
caps runaway input. If your agent runs recon, this is the shape of the answer.

### Built with

- [Bun](https://bun.sh) + [TypeScript](https://www.typescriptlang.org)
- [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) (stdio transport)
- [zod](https://zod.dev) for input validation
- [ProjectDiscovery](https://projectdiscovery.io) binaries: subfinder, dnsx, naabu, httpx, katana, nuclei, tlsx, shuffledns

---

## 🛠️ Tools

| Tool | Binary | What it does |
|---|---|---|
| `subfinder` | subfinder | Passive subdomain enumeration |
| `dnsx` | dnsx | Fast DNS probing and resolution |
| `naabu` | naabu | Port scanning (`scanType`: `"c"` connect scan unprivileged default, `"s"` SYN scan needs `CAP_NET_RAW`) |
| `httpx` | httpx | HTTP probing + tech detection (wappalyzer) |
| `katana` | katana | Web crawling and endpoint discovery |
| `nuclei` | nuclei | Vulnerability scanning -- **destructive-gated** (`confirm: true` required); template selection via `-id`, `-duc` always on; findings no longer reported as errors |
| `tlsx` | tlsx | TLS probing |
| `shuffledns` | shuffledns | Active subdomain brute-force with a wordlist |
| `bug_bounty_workflow` | composite | Chained recon workflow (now timeout-safe) |

All 9 tools verified live via `tools/list` + one live `tools/call` per binary (`bun driver.ts`).

---

## 🚀 Getting started

### Prerequisites

- [Bun](https://bun.sh) ≥ 1.4
- The ProjectDiscovery binaries — install via [`pdtm`](https://github.com/projectdiscovery/pdtm) (`pdtm -ia`) or your package manager, then point the server at them

### Installation

```sh
git clone https://github.com/toxicwind/pd-mcp.git
cd pd-mcp
bun install
export PD_TOOLS_DIR="$HOME/.pdtm/go/bin"   # where your PD binaries live
```

### Run

```sh
bun src/index.ts        # stdio MCP server — plug into any MCP client
```

Claude Code / Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "pd-mcp": {
      "command": "bun",
      "args": ["/path/to/pd-mcp/src/index.ts"],
      "env": { "PD_TOOLS_DIR": "/home/you/.pdtm/go/bin" }
    }
  }
}
```

---

## ⚡ 30-second proof

```sh
# server answers tools/list over stdio (9 tools)
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | timeout 25 bun src/index.ts | grep -o '"name":"[a-z_]*"' | sort -u
# "name":"bug_bounty_workflow" "name":"dnsx" "name":"httpx" "name":"katana"
# "name":"naabu" "name":"nuclei" "name":"shuffledns" "name":"subfinder" "name":"tlsx"

# one live call per binary, end to end
bun driver.ts           # exits non-zero on any failure
```

---

## ⚙️ Configuration

| Variable | Default | What it does |
|---|---|---|
| `PD_TOOLS_DIR` | `/home/toxic/.pdtm/go/bin` | Directory containing the PD binaries |
| `SHUFFLEDNS_BIN` | `/home/toxic/go/bin/shuffledns` | shuffledns lives outside pdtm's dir |
| `PD_<NAME>_BIN` | — | Per-binary override, e.g. `PD_HTTPX_BIN=/custom/path/httpx` |

Timeouts are per-tool and non-negotiable: subfinder/dnsx/httpx/tlsx 5 min, katana/naabu/shuffledns 10 min, nuclei 15 min.

---

## 🧬 What changed from upstream

Fork of [`intelligent-ears/pd-tools-mcp`](https://github.com/intelligent-ears/pd-tools-mcp) (MIT):

- **Estate binary resolution** — absolute paths via `PD_TOOLS_DIR`/`SHUFFLEDNS_BIN`/`PD_<NAME>_BIN`; clear error when a binary is missing
- **No-shell spawns with timeouts** — one shared timeout-guarded runner; no more hanging the MCP client
- **Input validation** — domains/hosts/ports validated and capped at the tool boundary; stdin payloads deduplicated and newline-stripped
- **New tools**: `tlsx` (TLS probing), `shuffledns` (active subdomain brute-force)
- **naabu**: `scanType` param (`"c"` connect / `"s"` SYN)
- **nuclei**: `-id` template selection, `-duc` always on, findings ≠ errors
- **httpx**: headless-chrome `screenshot` flag replaced with `techDetect` (wappalyzer)
- Kept upstream's `bug_bounty_workflow` composite (now timeout-safe)
- Configurable rate limiting
- **Nuclei destructive gate** -- `nuclei` requires `confirm: true` in the tool arguments; without it the call is refused with a clear error. Vulnerability scanning is active and potentially intrusive -- the gate forces explicit opt-in on every invocation
- **Heavy-scan concurrency gate** -- `naabu`, `nuclei`, and `shuffledns` share a 2-slot semaphore; extra heavy scans queue instead of stampeding the host
- **Startup binary check** -- the server validates all 8 binaries at launch and exits with a clear message naming what is missing, instead of failing mid-call

---

## 🗺️ Roadmap

- [x] 8 PD tools + composite behind MCP stdio
- [x] No-shell timeout-guarded runner, input validation, absolute binary resolution
- [x] tlsx + shuffledns tools, nuclei/naabu/httpx hardening
- [ ] uncover (Shodan-style) tool
- [ ] Streaming progress for long scans (nuclei/katana)
- [ ] SSE/HTTP transport alongside stdio

---

## 🤝 Contributing

Keep the contract: no shell spawns (everything through `src/tools/runner.ts`), every new tool gets input validation + a timeout + a `driver.ts` case. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.
Upstream: [`intelligent-ears/pd-tools-mcp`](https://github.com/intelligent-ears/pd-tools-mcp) (MIT).

---

## 📬 Contact

toxicwind — [@toxicwind](https://github.com/toxicwind). Bugs and feature requests via [issues](https://github.com/toxicwind/pd-mcp/issues).

---

## 🙏 Acknowledgments

- [intelligent-ears/pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp) — the upstream this forks
- [ProjectDiscovery](https://projectdiscovery.io) — the toolkit this serves

---

⭐ If your agents do recon, give it a star!
