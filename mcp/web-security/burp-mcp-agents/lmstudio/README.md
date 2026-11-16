# LM Studio Backend (Local OpenAI-Compatible)

This backend connects LM Studio's local OpenAI-compatible API to Burp MCP Server via a small Python agent.

All traffic stays on your machine.

---

## What you get

- Passive vulnerability discovery
- IDOR / auth bypass / SSRF / logic flaw triage
- Automated report writing from Burp evidence
- Full local data control
- Zero cloud dependency

---

## Requirements

| Component | Required |
|----------|----------|
| Burp Suite | Community or Pro |
| Burp MCP Server | Enabled |
| Caddy | Reverse proxy |
| LM Studio | Installed |
| Python 3.10+ | Required |

## Ports

- Burp MCP Server: `127.0.0.1:9876`
- Caddy proxy: `127.0.0.1:19876`
- LM Studio API: `127.0.0.1:1234` (default)

---

## Architecture

```

Burp MCP Server -> Caddy -> Python MCP Agent -> LM Studio (OpenAI API)

```

---

## 1. Install LM Studio

https://lmstudio.ai

Download a model and open the **Local Server** tab.

Enable the **OpenAI-compatible API server** and start it. The default base URL is:

```
http://127.0.0.1:1234/v1
```

Verify the server and model list:

```bash
curl -s http://127.0.0.1:1234/v1/models
```

Pick a model id from the response.

---

## 2. Install dependencies

```bash
cd lmstudio
python3 -m venv .venv
source .venv/bin/activate
pip install -r ../requirements.txt
```

---

## 3. Start Caddy

Follow:

```
common/caddy_setup.md
```

---

## 4. Run the agent

```bash
python3 lmstudio_mcp_agent.py <model-id>
```

Optional overrides:

```bash
python3 lmstudio_mcp_agent.py <model-id> --lmstudio http://127.0.0.1:1234/v1 --api-key lm-studio
```

---

## Optional launcher

To simplify startup and auto-shutdown of Caddy, use the provided launcher.

Source it into your shell:

```bash
source /path/to/burp-mcp-agents/lmstudio/burplmstudio.sh
```

Then run:

```bash
burplmstudio <model-id>
```

This will:
- Start Caddy
- Launch the LM Studio MCP agent
- Automatically stop Caddy when the agent exits

To make this available in every shell, add the `source` line to your `~/.zshrc`.

---

## Quick verification

1) Confirm the SSE proxy works:

```bash
curl -i http://127.0.0.1:19876/sse
```

2) Confirm LM Studio is reachable:

```bash
curl -s http://127.0.0.1:1234/v1/models
```

3) Confirm the agent connects and lists tools:

```bash
python3 lmstudio_mcp_agent.py <model-id>
```

You should see a tool list after connection.

---

## Test it

```
From Burp history, find endpoints that use numeric IDs and lack Authorization headers.
```

```
Using Burp MCP, identify possible SSRF parameters and rank them by risk.
```

```
From Burp evidence, write a full vulnerability report with reproduction, impact and remediation.
```

---

## Troubleshooting

- 403 or Origin errors: Caddy is not running or not used.
- Connection refused to LM Studio: make sure the Local Server is started.
- Model not found: verify the model id from `/v1/models`.
- Empty tool list: Burp MCP Server extension is not enabled.

---

## Example models

Use any instruction-tuned model you have loaded in LM Studio. Examples:

| Model | Notes |
|------|------|
| llama-3.1-8b-instruct | Small, fast |
| qwen2.5-14b-instruct | Mid size |
| llama-3.1-70b-instruct | Large, high VRAM |

---

## Why LM Studio

LM Studio provides a local OpenAI-compatible API with an easy GUI, so you can run models locally while keeping Burp data on your machine.
