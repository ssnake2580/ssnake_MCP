<!-- Satellite context file — extends the global hub (~/.claude/CLAUDE.md | ~/.pi/agent/AGENTS.md). Host-neutral; project-specific only. Do not duplicate hub standards here. -->

# Spoor

> An autonomous DFIR agent that follows the forensic trail an intruder leaves behind — and runs it to ground. Spoor drives SANS SIFT forensic tooling (Volatility 3, Sleuth Kit, RegRipper, plaso, YARA) through a purpose-built **MCP server**, orchestrated by a **LangGraph multi-agent graph** — a Lead Investigator routing triage, timeline, IOC-correlation, and reporter specialists over a shared case state. Every claim is either **backed by a verifiable tool execution or explicitly labeled an inference** — enforced in code, not in a prompt.

Built for the SANS **"FIND EVIL!"** hackathon (Devpost, 2026). Python · MCP · LangGraph · SIFT.

*Spoor:* the track or scent trail an animal leaves — follow the spoor to hunt the quarry. Here: follow forensic artifacts to the threat.

**Live proof-site:** https://spoor.rectorspace.com — recompute Spoor's real SHA-256 audit chain in your browser, then tamper a byte and watch the verdict break. No trust required.

## Stack

Python (`pyproject.toml`, `uv.lock`) · LangGraph (multi-agent graph) · MCP server (forensic tooling) · SANS SIFT (Volatility 3, Sleuth Kit, RegRipper, plaso, YARA) · `Makefile` · web (proof-site).

## Common Commands

```bash
make <recipe>         # see Makefile
uv sync
uv run pytest
```

## Structure

`spoor/` (agent + MCP server) · `spoor_sift/` · `tests/` · `scripts/` · `runs/` (case outputs) · `datasets/` · `evidence/` · `web/` (proof-site) · `docs/` · `SPEC.md` · `PLAN.md` · `accuracy_report.md` · `assets/`.

## Notes

- Groundedness is enforced in code: every claim cites a tool execution or is labeled inference — never a bare LLM assertion.
- The proof-site recomputes the SHA-256 audit chain client-side; tampering breaks the verdict — demonstrates the verifiable-audit design.