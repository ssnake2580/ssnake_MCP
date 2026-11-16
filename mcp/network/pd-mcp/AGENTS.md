# AGENTS.md — pd-mcp

Instructions for AI agents working in this repository.

## What this is

An MCP (Model Context Protocol) server that exposes ProjectDiscovery's
recon/security binaries as tools for AI agents: `subfinder`, `dnsx`, `naabu`,
`httpx`, `katana`, `nuclei`, `tlsx`, `shuffledns`, plus a composite
`bug_bounty_workflow`. Fork of `intelligent-ears/pd-tools-mcp`, hardened for
production agent use.

## Build / test

```bash
bun install
bun run build          # tsc -> build/index.js
bun src/index.ts       # run the stdio MCP server directly
```

Typecheck: `bunx tsc --noEmit`

## Architecture

- `src/index.ts` — MCP server wiring (SDK `Server`, stdio transport).
  Tool handlers live here; executors live in `src/tools/`.
- `src/tools/runner.ts` — the only place binaries are spawned. Everything
  goes through `runBinary()`: absolute path, argv array, **never a shell**,
  timeout-guarded with SIGKILL. Input guards (`cleanDomain`, `cleanList`,
  `cleanPortSpec`) are defense-in-depth at the tool boundary.
- `src/tools/*.ts` — one executor per binary. Pure arg-building + output
  parsing; no process logic outside `runner.ts`.
- `src/workflows/bug-bounty.ts` — composite pipeline chaining the tools.

## Binary resolution

Binaries are resolved at startup, not on PATH:

| Variable | Default |
|---|---|
| `PD_TOOLS_DIR` | `/home/toxic/.pdtm/go/bin` |
| `SHUFFLEDNS_BIN` | `/home/toxic/go/bin/shuffledns` |
| `PD_<NAME>_BIN` | per-binary override, e.g. `PD_HTTPX_BIN=/opt/httpx` |

The server validates all 8 binaries at launch and exits naming what's
missing. Don't bypass the startup check — a clear launch error beats a
mysterious mid-call failure.

## Safety rules (non-negotiable)

1. **`nuclei` requires `confirm: true` in tool args, every call.** This is a
   destructive-operation gate. Never add a bypass, default it on, or document
   a workaround. The gate is the feature.
2. **Heavy scans (`naabu`, `nuclei`, `shuffledns`) share a 2-slot semaphore**
   (`withHeavyGate`). Don't widen it without measuring host impact.
3. **No shell spawns, ever.** `spawn()` takes an absolute binary path and an
   argv array. If you're tempted to add `shell: true` or string-concat a
   command, stop — that's the bug this fork exists to prevent.
4. **Timeouts are load-bearing.** subfinder/dnsx/httpx/tlsx: 5 min;
   katana/naabu/shuffledns: 10 min; nuclei: 15 min. A hanging MCP call hangs
   the agent client.
5. **Validate at the boundary.** Domains, ports, and list inputs go through
   the `clean*` guards in `runner.ts`. New tools must do the same.

## Conventions

- Bun + TypeScript. No new Python, no new npm-only tooling.
- Tool results are JSON-serializable via `toolResult()` — keep them
  pipe-friendly for agent composition (`jq`-able, no ANSI codes).
- Keep `src/tools/` executors thin: arg building + output parsing only.
- Update README's tool table when adding/removing tools.
- Commits: imperative mood, scope prefix (`nuclei:`, `runner:`, `docs:`).

## Don't

- Don't add network calls to the server itself (it wraps local binaries).
- Don't cache scan results across calls (stale recon is worse than slow recon).
- Don't change the nuclei gate or the heavy-scan semaphore without a
  design note in the PR.
