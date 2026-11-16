# zap-mcp

A tiny MCP server that lets an AI agent do security testing with [ZAP](https://www.zaproxy.org).

Three tools. That's the whole thing:

| Tool | What it does |
|---|---|
| `zap_start` | Starts ZAP in Docker as an intercepting proxy and returns the proxy URL |
| `zap_get_alerts` | Returns what ZAP found in the traffic so far, grouped by alert, sorted by risk |
| `zap_stop` | Removes the container |

The idea: the agent does the tedious part of security testing, the manual clicking around. It drives a real browser *through* ZAP, registering users, logging in, searching, filling baskets, and ZAP passively scans every request and response on the way. Then the agent reads the alerts and triages them. You can tell it what to focus on ("the checkout flow", "everything after login"). Nothing is attacked: there is no active scanning, so it is safe by default.

## Quick start

Requirements: Node 20+ and Docker.

```bash
claude mcp add zap -- npx -y github:omerlh/zap-mcp
```

That's it. Ask Claude to "start ZAP" and tell it what to test. For Cursor or any other MCP client, add the same command under `mcpServers`:

```json
{ "mcpServers": { "zap": { "command": "npx", "args": ["-y", "github:omerlh/zap-mcp"] } } }
```

The agent also needs a browser it can point at a proxy. [agent-browser](https://github.com/vercel-labs/agent-browser) works well (`npm i -g agent-browser && agent-browser install`).

## Example: test OWASP Juice Shop with Claude Code

Start the deliberately vulnerable target:

```bash
docker run -d --name juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Then ask Claude Code:

> Start ZAP. Explore the Juice Shop at http://host.docker.internal:3000 through the ZAP proxy: browse the shop, search for products, register and log in. Then get the alerts and triage them: what is real, what is noise, and what would you fix first?

`host.docker.internal` matters: ZAP runs in Docker, so `localhost` would point at ZAP's own container.

Claude calls `zap_start`, browses through the proxy with [agent-browser](https://github.com/vercel-labs/agent-browser), calls `zap_get_alerts`, and answers with a triage. Point the browser at the proxy like this:

```bash
agent-browser --proxy http://127.0.0.1:8080 --ignore-https-errors open http://host.docker.internal:3000
```

### What it found

A browser session through the proxy (register, log in, search, add two items to the basket, open the basket and profile) produced **63 alerts, which group into 7 distinct findings**:

```
[Medium/Medium Cross-Domain Misconfiguration] x27       Access-Control-Allow-Origin: *
[Medium/High   Content Security Policy (CSP) Header Not Set] x3
[Medium/Medium Missing Anti-clickjacking Header] x2
[Medium/High   Session ID in URL Rewrite] x8            socket.io ...&sid=...
[Low/Low       Timestamp Disclosure - Unix] x18
[Low/Medium    X-Content-Type-Options Header Missing] x4
[Low/Medium    Private IP Disclosure] x1                /rest/admin/application-configuration
```

Grouping matters: an agent reading 63 raw alerts burns its context, and one reading 7 can triage them.

## Triage skill

Finding alerts is half the problem; the other half is a report people act on. The repo ships a triage skill that follows a PoC-or-GTFO rule (it tries to reproduce each alert with a minimal, non-destructive request and drops what it cannot prove), rates what survives with the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) (likelihood x impact), and writes a structured report.

- **Any MCP client:** use the `zap_triage_report` prompt.
- **Claude Code skill:** `cp -r skills/zap-triage ~/.claude/skills/`

## Ready-made prompt: the full loop

Security works best as part of how the team ships, not as an outsider handing over a list. The `zap_fix_loop` prompt (or the `skills/zap-fix-loop` skill) is for a coding agent working in your repo: run the app, scan it through ZAP, prove each finding, fix it on a branch, replay the proof to verify the fix, re-scan, and prepare a pull request with before/after proof. It never pushes until you say so, and only targets a local or test app.

## Notes

- Only point it at apps you are allowed to test.
- Alerts are grouped by name so an agent's context isn't flooded with one entry per URL.
- If the MCP server restarts while ZAP keeps running, the next `zap_get_alerts` picks the running container back up.
- `ZAP_IMAGE` overrides the image (default `zaproxy/zap-stable`).
- The API key is random per run, and the proxy listens on `127.0.0.1` only.

## Roadmap

- `zap_spider`, to crawl a target
- Active scan, behind an explicit opt-in
