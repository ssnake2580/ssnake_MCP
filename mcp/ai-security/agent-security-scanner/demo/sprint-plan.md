# agent-security-scanner-mcp — 6-Week Execution Plan

**Date:** February 18, 2026 **Team:** 3 engineers \+ Claude Code (bootstrapped) **Package:** `agent-security-scanner-mcp` (npm) — keep existing name, no rebrand **Current state:** v3.9.0 — 1700+ rules, AST \+ taint, 97.7% precision, 432 tests, 10 MCP tools **Primary goal:** Maximize adoption (installs, stars, community) **Target:** All AI coding agents — Claude Code, Cursor, Windsurf, Cline, OpenClaw, OpenCode, Cody

---

## Strategic Premise

### Why no rebrand

Rebranding to "ClawProof" would split distribution, burn 1-2 weeks on migration logistics, and narrow our positioning to OpenClaw-only. The current name already has npm traction, existing installs across 8 MCP clients, and broad SEO surface area. OpenClaw is a growth vector, not our identity.

### What we're actually competing on

The competitive landscape has four players. Each has a gap we can exploit:

| Competitor | Strength | Exploitable gap |
| :---- | :---- | :---- |
| **SecureClaw** (Adversa AI) | OpenClaw config auditing, OWASP/MITRE mapping, PR machine | Zero code analysis, zero package hallucination detection, no auto-fix, no MCP support |
| **Snyk mcp-scan** | Research credibility, ToxicSkills data, LLM-powered scanning, enterprise distribution | Not an OpenClaw plugin, no auto-fix, behind a commercial platform, no real-time monitoring |
| **Cisco Skill Scanner** | LLM semantic analysis, VirusTotal integration, official ClawHub pipeline integration | Enterprise-only posture, no MCP support, no package hallucination detection, no auto-fix |
| **AgentSec** | OWASP mapping, SARIF output, multi-scanner architecture | No AST/taint, no hallucination detection, no auto-fix, no OpenClaw plugin |

**Our actual moat:** We are the only tool that does deep static code analysis (AST \+ taint \+ cross-file) AND package hallucination detection AND prompt injection defense AND auto-fix AND works across all AI coding agents via MCP AND can be deployed as an OpenClaw plugin. Nobody else covers this full stack.

**Our weakness:** No research credibility, no press coverage, no framework compliance mapping, small community. These are the gaps we close in 6 weeks.

### The adoption strategy

We don't win by building more features. We win by producing a piece of research so compelling that the community comes to us. Then we make the product easy to install and impossible to ignore.

**The play:**

1. **Week 1-2:** Stabilize, wire the daemon, ship the OpenClaw plugin  
2. **Week 3:** Scan every skill on ClawHub. Publish results. This is the most important thing we do.  
3. **Week 4:** Config auditor \+ behavioral skill (complete the OpenClaw story)  
4. **Week 5:** OWASP ASI mapping, polish, content  
5. **Week 6:** Launch week — ClawHub, HN, Reddit, Discord blitz

---

## What We Build (and What We Don't)

### Build

| Deliverable | Why it matters for adoption |
| :---- | :---- |
| **ClawHub Skills Report** — scan 3,000+ skills, publish grades, findings, dashboard | Single highest-leverage activity. Earns media, establishes credibility, drives inbound |
| **OpenClaw Plugin** — native plugin with skill scanning, config auditing, kill switch | Reaches OpenClaw's 200K+ star community directly |
| **OpenClaw Behavioral Skill** — 20+ security rules loaded into agent context | Lightweight entry point, installs in 30 seconds |
| **Config Auditor** — 60+ checks for OpenClaw gateway, files, tools, credentials | Table-stakes to compete with SecureClaw on their turf |
| **OWASP ASI Top 10 mapping** — formal framework compliance for all findings | Unlocks enterprise conversations, matches SecureClaw's positioning |
| **Python daemon wiring** — connect the built-but-unused daemon for 5-10x throughput | Required for batch scanning thousands of skills |
| **Landing page** (on existing domain or GitHub Pages) | Conversion point for all traffic |

### Don't Build (Yet)

| Cut item | Why |
| :---- | :---- |
| ~~ClawProof rebrand~~ | Distribution split, weeks of migration, narrows positioning |
| ~~Cloud dashboard~~ | Premature — build after adoption proves demand |
| ~~Threat intelligence feed~~ | Requires sustained infra investment, no users to sell to yet |
| ~~VS Code extension~~ | Nice-to-have, not adoption driver |
| ~~Semantic prompt injection (ONNX)~~ | R\&D project, not shipping priority |
| ~~Policy engine~~ | Enterprise feature, build when enterprises show up |

---

## 6-Week Sprint Plan

### Week 1: Stabilize \+ Wire (Feb 19-25)

**Goal:** All tests green, daemon wired, 5x+ throughput for batch scanning.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 1.1 | Fix all failing tests from PR \#8 path relocation | Eng 1 | 1 day | CRITICAL |
| 1.2 | Wire Python daemon into MCP tools (replace execFileSync) | Eng 1 | 2 days | CRITICAL |
| 1.3 | Daemon lifecycle in index.js — lazy start, shutdown, health check, signal handlers | Eng 1 | 1 day | HIGH |
| 1.4 | Standardize file layout (resolve root vs mcp-server/ confusion) | Eng 1 | 0.5 day | HIGH |
| 1.5 | Add `scan_prompt_injection` action to daemon.py | Eng 2 | 1 day | HIGH |
| 1.6 | Add daemon health check to `doctor` command | Eng 2 | 0.5 day | MEDIUM |
| 1.7 | Write benchmark script: scan 100 files, measure time with/without daemon | Eng 2 | 0.5 day | HIGH |
| 1.8 | Update README: add OpenClaw section, improve quick start, add badges | Eng 2 | 1 day | HIGH |
| 1.9 | CI: ensure tests pass on Node 18/20/22 \+ Python 3.10+ | Eng 2 | 0.5 day | HIGH |

**Exit criteria:**

- 432+ tests passing, CI green  
- Daemon wired and delivering measurable speedup (target: 5x on repeat scans)  
- `npx agent-security-scanner-mcp doctor` reports daemon health  
- README reflects OpenClaw support alongside existing MCP clients

---

### Week 2: OpenClaw Plugin \+ Skill (Feb 26-Mar 4\)

**Goal:** Installable OpenClaw plugin and behavioral skill. `clawhub install` works.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 2.1 | Plugin skeleton: `openclaw.plugin.json`, `package.json` with `openclaw.extensions`, `index.ts` entry | Eng 1 | 1 day | CRITICAL |
| 2.2 | Plugin config schema for `openclaw.json` — enable/disable features, severity threshold, exclude paths | Eng 1 | 0.5 day | HIGH |
| 2.3 | Wire existing `scan_security` as OpenClaw tool (file scanning) | Eng 1 | 0.5 day | HIGH |
| 2.4 | Wire `scan_agent_prompt` as OpenClaw tool (prompt injection) | Eng 1 | 0.5 day | HIGH |
| 2.5 | Wire `check_package` \+ `scan_packages` as OpenClaw tools | Eng 1 | 0.5 day | HIGH |
| 2.6 | New tool: `scan_agent_action` — pre-execution safety for bash/file/HTTP/cron | Eng 1 | 1 day | HIGH |
| 2.7 | Plugin health check \+ version reporting | Eng 1 | 0.5 day | MEDIUM |
| 2.8 | Write `skills/openclaw/SKILL.md` — 20+ behavioral security rules (\~1,200 tokens) | Eng 2 | 1.5 days | HIGH |
| 2.9 | Behavioral rules: pre-exec safety, prompt injection defense, credential hygiene, inter-agent safety | Eng 2 | (included in 2.8) | HIGH |
| 2.10 | CLI commands: `scan-skill <path>`, `audit`, `harden` | Eng 2 | 1 day | HIGH |
| 2.11 | `init openclaw` command — install plugin \+ skill to `~/.openclaw/` | Eng 2 | 0.5 day | HIGH |
| 2.12 | Integration tests: install plugin in OpenClaw, run tools, verify output | Eng 2 | 1 day | HIGH |

**Exit criteria:**

- `npx agent-security-scanner-mcp init openclaw` installs plugin \+ skill  
- Agent can call all security tools from within OpenClaw  
- Behavioral skill loads cleanly, stays under 1,300 tokens  
- All existing MCP functionality untouched (backward compat)

---

### Week 3: The ClawHub Scan — Our Big Research Play (Mar 5-11)

**Goal:** Scan every skill on ClawHub. Produce a public report. This is the single most important week.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 3.1 | Build ClawHub scraper — clone/download all skills from ClawHub registry | Eng 1 | 1 day | CRITICAL |
| 3.2 | Build batch scanning pipeline — scan all skills through our engine (AST \+ taint \+ regex \+ hallucination \+ prompt injection) | Eng 1 | 2 days | CRITICAL |
| 3.3 | Build grading system — A-F security grades per skill, aggregate stats | Eng 1 | 1 day | CRITICAL |
| 3.4 | Run the full scan (target: 3,500+ skills) — collect findings, verify top results manually | Eng 1 | 1 day | CRITICAL |
| 3.5 | Write blog post: "We Scanned Every Skill on ClawHub. Here's What Our Engine Found." | Eng 2 | 2 days | CRITICAL |
| 3.6 | Build public dashboard — static site (GitHub Pages) showing grades for every scanned skill | Eng 2 | 2 days | HIGH |
| 3.7 | Generate comparison data: what our engine catches vs what regex-only or config-only tools miss | Eng 2 | 1 day | HIGH |
| 3.8 | Package the scanning pipeline as repeatable: `npx agent-security-scanner-mcp scan-clawhub` | Eng 1 | 0.5 day | MEDIUM |

**Exit criteria:**

- 3,500+ skills scanned, findings validated  
- Blog post ready with stats: X% with vulns, Y critical, Z hallucinated packages, top categories  
- Public dashboard live showing per-skill grades  
- Clear comparison: "Snyk found N issues in their ToxicSkills study. Our engine found N+M, including these categories they missed."

**Content strategy for the blog:**

- Lead with the data, not the product. Make it genuinely useful research.  
- Show specific examples (anonymized if needed) of what deep code analysis catches that config auditing misses.  
- Include methodology so it's reproducible and credible.  
- End with: "You can run this yourself: `npx agent-security-scanner-mcp scan-skill <path>`"  
- Target publications: Hacker News, r/netsec, r/ClaudeAI, r/OpenClaw, OpenClaw Discord, security Twitter/Bluesky

**Why this matters more than any feature:**

- Snyk's ToxicSkills study (3,984 skills) generated massive press coverage and credibility  
- Nobody has done this with deep AST \+ taint analysis — Snyk used LLM-powered scanning, Cisco used behavioral \+ LLM  
- Our engine can catch things theirs can't: interprocedural taint flows, package hallucinations in skill dependencies, cross-file data exfiltration patterns  
- The dashboard becomes a permanent resource that drives recurring traffic  
- It demonstrates our engine's value better than any feature comparison table ever could

---

### Week 4: Config Auditor \+ Hardening (Mar 12-18)

**Goal:** Complete the security trifecta — code scanning \+ config auditing \+ behavioral rules.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 4.1 | `src/config-auditor.js` — parse and audit `openclaw.json` | Eng 1 | 2 days | CRITICAL |
| 4.2 | Gateway checks: bind mode, auth, token strength, Tailscale Funnel exposure | Eng 1 | (included in 4.1) | CRITICAL |
| 4.3 | File permission checks: credentials, config, session transcripts, memory files | Eng 1 | 0.5 day | HIGH |
| 4.4 | Tool policy checks: permissive groups, sandbox settings, elevated tools | Eng 1 | 0.5 day | HIGH |
| 4.5 | DM/group policy checks: open access, pairing bypass, mention gating | Eng 1 | 0.5 day | HIGH |
| 4.6 | Hook security, mDNS exposure, plugin policy checks | Eng 1 | 0.5 day | MEDIUM |
| 4.7 | Credential storage audit: plaintext secrets, exposed API keys in .env/config | Eng 1 | 0.5 day | HIGH |
| 4.8 | Auto-hardening: `npx agent-security-scanner-mcp harden --fix` | Eng 2 | 1 day | HIGH |
| 4.9 | Rug pull detection: baseline hash installed skills, alert on unexpected changes | Eng 2 | 1 day | MEDIUM |
| 4.10 | Kill switch: prevent Gateway startup if critical findings are unresolved | Eng 2 | 0.5 day | MEDIUM |
| 4.11 | Output formats: JSON, SARIF, human-readable summary | Eng 2 | 0.5 day | HIGH |
| 4.12 | `npx agent-security-scanner-mcp audit` command — run all config checks | Eng 2 | 0.5 day | HIGH |
| 4.13 | Integration tests for config auditor (mock openclaw.json configs) | Eng 2 | 1 day | HIGH |

**Exit criteria:**

- `audit` command produces 60+ checks covering all OpenClaw security surfaces  
- `harden --fix` auto-fixes the most critical misconfigurations  
- Rug pull detector baselines skill hashes and alerts on changes  
- SARIF output for CI/CD integration

---

### Week 5: Framework Mapping \+ Polish (Mar 19-25)

**Goal:** OWASP ASI compliance, documentation, landing page, prep for launch.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 5.1 | Map all findings to OWASP Agentic Security Initiative (ASI) Top 10 | Eng 1 | 1.5 days | CRITICAL |
| 5.2 | Map to MITRE ATLAS agentic TTPs (as many as applicable) | Eng 1 | 1 day | HIGH |
| 5.3 | Generate compliance summary in audit output: "X/10 OWASP ASI categories covered" | Eng 1 | 0.5 day | HIGH |
| 5.4 | Add known CVE checks: CVE-2026-25253, ClawHavoc signatures, known malicious patterns | Eng 1 | 1 day | HIGH |
| 5.5 | Landing page: hero, features, install command, comparison table, ClawHub report link | Eng 2 | 2 days | CRITICAL |
| 5.6 | Write blog \#2: "Why Config Auditing Isn't Enough: Deep Code Analysis for AI Agent Security" | Eng 2 | 1.5 days | HIGH |
| 5.7 | Record 2-minute demo video: install → scan malicious skill → see findings → auto-fix | Eng 2 | 0.5 day | HIGH |
| 5.8 | Update all `init` commands to reflect new capabilities | Eng 1 | 0.5 day | MEDIUM |
| 5.9 | End-to-end testing: fresh machine → install → scan → audit → fix workflow | Both | 1 day | CRITICAL |

**Exit criteria:**

- OWASP ASI Top 10 formally mapped (aim for 8+/10 coverage)  
- Landing page live with clear value prop and install instructions  
- Demo video ready for social distribution  
- All `init` commands working for all 9 supported clients

---

### Week 6: Launch (Mar 26-Apr 1\)

**Goal:** Ship to ClawHub. Maximum visibility. Drive installs.

| \# | Task | Owner | Est | Priority |
| :---- | :---- | :---- | :---- | :---- |
| 6.1 | Publish to ClawHub marketplace | Eng 1 | 0.5 day | CRITICAL |
| 6.2 | npm publish: bump to v4.0.0 (signals major milestone, new capabilities) | Eng 1 | 0.5 day | CRITICAL |
| 6.3 | Submit Hacker News post: link to ClawHub research blog | Eng 2 | 0.5 day | CRITICAL |
| 6.4 | Post to r/netsec, r/ClaudeAI, r/OpenClaw, r/cybersecurity | Eng 2 | 0.5 day | HIGH |
| 6.5 | Post in OpenClaw Discord \#security channel | Eng 2 | 0.5 day | HIGH |
| 6.6 | PR to OpenClaw docs: recommend scanner in security page | Eng 1 | 0.5 day | MEDIUM |
| 6.7 | Submit to awesome-openclaw-skills | Eng 1 | 0.25 day | MEDIUM |
| 6.8 | Reach out to security researchers who covered OpenClaw (Snyk, Cisco, CrowdStrike bloggers) | Eng 2 | 1 day | HIGH |
| 6.9 | Publish comparison page: agent-security-scanner-mcp vs SecureClaw vs Snyk mcp-scan vs AgentSec | Eng 2 | 1 day | HIGH |
| 6.10 | Monitor installs, respond to issues/PRs, community engagement | Both | ongoing | CRITICAL |
| 6.11 | Re-run ClawHub scan with latest skills, update dashboard | Eng 1 | 0.5 day | MEDIUM |

**Exit criteria:**

- Live on ClawHub, npm v4.0.0 published  
- Blog post and dashboard generating traffic  
- Community engagement started (Discord, Reddit, GitHub issues)  
- First wave of installs tracked

---

## Distribution Strategy: One Codebase, Four Surfaces

```
agent-security-scanner-mcp
├── MCP Server        ← EXISTING (Claude Code, Cursor, Windsurf, Cline, etc.)
├── CLI               ← EXISTING + ENHANCED (CI/CD, scripts, batch scanning)
├── OpenClaw Plugin   ← NEW (in-process, gateway-level)
└── OpenClaw Skill    ← NEW (behavioral rules in agent context)
```

All four ship from the same npm package. One install, one codebase, one community. No distribution split.

**Why this matters:** Every other competitor is single-surface. SecureClaw is OpenClaw-only. Snyk mcp-scan is CLI-only. Cisco is enterprise-only. We're the only tool that works everywhere AI coding agents run.

---

## The Content Playbook (Adoption Engine)

Content is our marketing team. With 2 engineers and no marketing budget, every piece of content must earn its place.

### Blog \#1: "We Scanned Every Skill on ClawHub" (Week 3\)

**Goal:** Establish credibility, generate press, drive inbound **Format:** Data-driven research report **Distribution:** HN, Reddit, OpenClaw Discord, security Twitter **Why it works:** Snyk's ToxicSkills study generated coverage in The Hacker News, Help Net Security, VentureBeat, and dozens of security blogs. Our version adds what theirs couldn't: deep AST \+ taint analysis findings. We're not competing with Snyk — we're extending their work with a different analysis approach.

Key angles:

- "Snyk found 36.8% of skills had flaws using LLM-powered scanning. We found X% using AST \+ taint analysis. Here's what each approach catches — and misses."  
- Specific examples of interprocedural taint flows that pattern matching misses  
- Hallucinated package names found in skill dependencies  
- A-F grades for every skill, searchable on our dashboard

### Blog \#2: "Why Config Auditing Isn't Enough" (Week 5\)

**Goal:** Position against SecureClaw without attacking them **Format:** Technical explainer with concrete examples **Distribution:** Same channels \+ tag SecureClaw conversation **Key argument:** Config auditing catches misconfigurations. Code scanning catches malicious intent. You need both. Here's a malicious skill that passes every config audit but fails code analysis.

### The Dashboard (Week 3, updated weekly)

**Goal:** Recurring traffic, permanent resource, community trust **Format:** Static site (GitHub Pages) — searchable, filterable **Content:** A-F grade for every ClawHub skill, breakdown by category, drill-down to findings **Moat:** If we update this weekly, we become the canonical "is this skill safe?" resource. Competitors would have to build equivalent scanning infrastructure to replicate it.

### Demo Video (Week 5\)

**Goal:** Show, don't tell **Format:** 2-minute terminal screencast **Flow:** Install → scan a known-malicious skill → see findings with CWE/OWASP refs → auto-fix → verify fix

---

## Architecture

```
+------------------------------------------------------------+
|                    OpenClaw Gateway                          |
|                                                             |
|  +----------------------+    +----------------------------+ |
|  |  Scanner Plugin      |    |   Security Skill           | |
|  |  (in-process)        |    |   (agent context)          | |
|  |                      |    |                            | |
|  |  - Skill scanner     |    |  - 20+ behavioral rules    | |
|  |  - Config auditor    |    |  - Pre-exec safety         | |
|  |  - Supply chain      |    |  - Prompt injection defense| |
|  |  - Rug pull watch    |    |  - Credential hygiene      | |
|  |  - Kill switch       |    |  - Package verification    | |
|  +----------+-----------+    +-------------+--------------+ |
|             |                              |                 |
+-------------+------------------------------+-----------------+
              |                              |
              v                              v
      +----------------------------------------------+
      |        agent-security-scanner-mcp Engine       |
      |                                                |
      |  +-------------+  +--------------------------+ |
      |  | Python       |  |  Node.js                 | |
      |  | Daemon       |  |  (MCP Server + CLI)      | |
      |  |              |  |                          | |
      |  | - AST parse  |  |  - scan-security         | |
      |  | - Taint trace|  |  - scan-prompt           | |
      |  | - Regex scan |  |  - scan-action (NEW)     | |
      |  | - Rule match |  |  - check-package         | |
      |  | - LRU cache  |  |  - fix-security          | |
      |  +-------------+  |  - audit (NEW)            | |
      |                    |  - scan-skill (NEW)       | |
      |                    |  - scan-clawhub (NEW)     | |
      |                    +--------------------------+ |
      |                                                |
      |  +------------------------------------------+  |
      |  |  Shared Assets                           |  |
      |  |  - 1700+ YAML rules                     |  |
      |  |  - 7 bloom filters (4.3M packages)      |  |
      |  |  - 120 fix templates                    |  |
      |  |  - OpenClaw threat rules (30+)          |  |
      |  |  - Config audit checks (60+)            |  |
      |  |  - OWASP ASI + MITRE ATLAS mappings     |  |
      |  +------------------------------------------+  |
      +------------------------------------------------+
```

### New Tools (in addition to existing 10\)

| Tool | Surface | Description |
| :---- | :---- | :---- |
| `scan_agent_action` | MCP \+ Plugin \+ Skill | Pre-execution safety check for bash/file/HTTP/cron commands |
| `audit_config` | CLI \+ Plugin | Audit OpenClaw gateway configuration (60+ checks) |
| `harden` | CLI \+ Plugin | Auto-fix critical misconfigurations |
| `scan_skill` | CLI \+ Plugin | Deep scan a ClawHub skill before installation |
| `scan_clawhub` | CLI | Batch scan entire ClawHub registry |

---

## Success Metrics

### Week 6 (Launch)

| Metric | Target | How we measure |
| :---- | :---- | :---- |
| npm weekly downloads | 2,000+ | npm stats |
| ClawHub installs (first week) | 500+ | ClawHub analytics |
| GitHub stars | 200+ | GitHub |
| Blog post views | 5,000+ | Analytics |
| HN front page | Yes/No | Manual |
| Tests passing | 100% | CI |
| Config audit checks | 60+ | Code count |
| OWASP ASI coverage | 8+/10 | Mapping document |

### Month 2 (Week 8\)

| Metric | Target |
| :---- | :---- |
| npm weekly downloads | 5,000+ |
| ClawHub installs | 5,000+ |
| GitHub stars | 500+ |
| Press/blog mentions | 3+ |
| Dashboard unique visitors | 2,000+ |

### Month 3 (Week 12\)

| Metric | Target |
| :---- | :---- |
| npm weekly downloads | 10,000+ |
| GitHub stars | 2,000+ |
| Community-contributed rules | 10+ |
| Inbound enterprise inquiries | 3+ |

---

## Risk Register

| \# | Risk | Likelihood | Impact | Mitigation |
| :---- | :---- | :---- | :---- | :---- |
| R1 | SecureClaw captures "default OpenClaw security tool" mindshare | HIGH | HIGH | Our research blog leapfrogs their PR. They can't replicate deep code analysis quickly. Ship Week 3 blog ASAP. |
| R2 | Snyk ships an OpenClaw-native plugin | MEDIUM | CRITICAL | Move fast. Our breadth (MCP \+ CLI \+ Plugin \+ Skill) is hard to replicate. Snyk optimizes for enterprise, not community. |
| R3 | OpenClaw plugin API changes (project moving to foundation) | MEDIUM | HIGH | Pin to specific OpenClaw version. Maintain compat layer. Watch releases daily. |
| R4 | ClawHub scan reveals nothing interesting (weak blog) | LOW | HIGH | **Our engine is deeper than Snyk's — we will find things. Validate top findings manually before publishing.** |
| R5 | False positives in ClawHub scan erode credibility | MEDIUM | HIGH | Manual verification of top 50 findings. Include methodology and FP rate in blog. Be honest about limitations. |
| R6 | Python engine adds deployment friction for users | MEDIUM | MEDIUM | Regex fallback without Python. Clear error messages. `doctor` command diagnoses issues. |
| R7 | ClawHub rejects our plugin listing | LOW | HIGH | Follow all guidelines. No false claims. Lead with value. |
| R8 | Daemon memory leaks during batch scanning | MEDIUM | MEDIUM | Health endpoint, auto-restart at 500MB, LRU cache capped at 200 entries. |
| R9 | VirusTotal/Gemini integration in ClawHub makes our scanning redundant | MEDIUM | MEDIUM | VirusTotal catches known malware. We catch code-level vulns, hallucinated packages, and taint flows. Different layers. |
| R10 | Nobody cares about another security scanner | MEDIUM | HIGH | **Lead with research, not product. The blog is the hook. The product is the follow-through.** |

---

## What Comes After (Week 7-12 Roadmap)

Sequence these based on what adoption data tells us. Don't commit until we see what works.

| Feature | Effort | Trigger to build |
| :---- | :---- | :---- |
| Weekly automated ClawHub scan \+ updated dashboard | 1 week | Dashboard gets \>1K visitors |
| GitHub Action for skill repos (scan on PR) | 1 week | 3+ community requests |
| Hallucination detection v2 (typosquatting scoring) | 2 weeks | Package hallucination findings resonate in blog |
| Claude Code hooks integration (post-tool-use auto-scan) | 1 week | Claude Code users ask for it |
| Rule authoring SDK (community flywheel) | 1 week | 5+ community rule contributions |
| ClawHub security badge ("Scanned by agent-security-scanner-mcp") | 1 week | ClawHub partnership discussion |
| Enterprise pilot: cloud dashboard \+ policy engine | 4 weeks | 3+ inbound enterprise inquiries |
| Threat intelligence feed (new malicious skills, attack patterns) | 2 weeks | Enterprise demand confirmed |

---

## Monetization (Not Yet, But Planned)

### Phase 1: Open Source Everything (Now \- Month 3\)

All scanning, all rules, auto-fix, plugin, skill, MCP server, CLI, dashboard — free and MIT.

**Goal:** Become the default. Get to 10K+ weekly downloads. Build community.

### Phase 2: Enterprise Layer (Month 3-6, only if demand is proven)

| Feature | Free | Team ($29/agent/mo) | Enterprise (Custom) |
| :---- | :---- | :---- | :---- |
| All local scanning \+ rules | ✅ | ✅ | ✅ |
| ClawHub dashboard access | ✅ | ✅ | ✅ |
| Cloud policy enforcement | — | ✅ | ✅ |
| Private rule repository | — | ✅ | ✅ |
| Threat intel feed | — | — | ✅ |
| SSO/SAML | — | — | ✅ |
| Compliance reports (SOC2, ISO) | — | — | ✅ |
| SLA \+ support | — | — | ✅ |

Don't build any of this until at least 3 enterprises ask for it. Open source adoption is the prerequisite, not a parallel track.

---

## Key Files to Modify

| File | Change | Sprint |
| :---- | :---- | :---- |
| `index.js` | Daemon lifecycle, shutdown hooks, new tool registration | Week 1 |
| `src/tools/*.js` (6 files) | Wire through daemon instead of execFileSync | Week 1 |
| `daemon.py` | Add `scan_prompt_injection` action | Week 1 |
| `src/daemon-client.js` | Connect to tools (currently unused) | Week 1 |
| `src/cli/doctor.js` | Add daemon health check | Week 1 |
| `package.json` | Update metadata, keywords, version | Week 1 |
| `README.md` | Major rewrite — OpenClaw section, broader positioning | Week 1 |
| **NEW:** `openclaw.plugin.json` | Plugin config schema | Week 2 |
| **NEW:** `src/plugin/index.ts` | OpenClaw plugin entry point | Week 2 |
| **NEW:** `skills/openclaw/SKILL.md` | 20+ behavioral security rules | Week 2 |
| **NEW:** `src/tools/scan-action.js` | Pre-execution safety tool | Week 2 |
| **NEW:** `src/clawhub-scanner.js` | Batch ClawHub scanning pipeline | Week 3 |
| **NEW:** `src/grading.js` | A-F security grading system | Week 3 |
| **NEW:** `src/config-auditor.js` | OpenClaw config auditing (60+ checks) | Week 4 |
| **NEW:** `src/hardener.js` | Auto-fix for config issues | Week 4 |
| **NEW:** `src/owasp-mapping.js` | OWASP ASI \+ MITRE ATLAS mapping | Week 5 |
| **NEW:** `docs/landing/` | Landing page (static site) | Week 5 |

---

## Daily Rhythm for the 6 Weeks

```
Morning:  Stand-up (5 min async) — what I shipped, what I'm building, any blockers
Build:    Deep work blocks (3-4 hours). Claude Code handles implementation. You review + steer.
Evening:  Push code, update sprint board, prep next day's Claude Code tasks
Friday:   Week retro — did we hit exit criteria? What shifts?
```

### Claude Code Usage Pattern

Claude Code is your third engineer. Use it for:

- **Implementation:** "Build the config auditor that checks these 60 items against openclaw.json"  
- **Test writing:** "Write tests for all 60 config audit checks"  
- **Scanning pipeline:** "Build a script that clones all ClawHub skills and runs our scanner against each"  
- **Blog draft:** "Here's the data from our scan. Draft the technical blog post."  
- **Landing page:** "Build a single-page site with hero, features grid, install command, comparison table"

Don't use Claude Code for: strategic decisions, prioritization calls, competitive positioning, or deciding what to cut.

---

## Sources

### OpenClaw Security Crisis

- [CrowdStrike: What Security Teams Need to Know About OpenClaw](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/)  
- [Cisco: Personal AI Agents Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare)  
- [VentureBeat: CISO Guide to OpenClaw](https://venturebeat.com/security/openclaw-agentic-ai-security-risk-ciso-guide)  
- [The Hacker News: OpenClaw Integrates VirusTotal](https://thehackernews.com/2026/02/openclaw-integrates-virustotal-scanning.html)  
- [Barrack.ai: Safe Way to Run OpenClaw](https://blog.barrack.ai/openclaw-security-vulnerabilities-2026/)  
- [Snyk: ToxicSkills Study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)  
- [Snyk: 280+ Leaky Skills](https://snyk.io/blog/openclaw-skills-credential-leaks-research/)  
- [Snyk: ClawHub Malicious Google Skill](https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/)

### Competitors

- [SecureClaw by Adversa AI (GitHub)](https://github.com/adversa-ai/secureclaw)  
- [SecureClaw launch (Help Net Security)](https://www.helpnetsecurity.com/2026/02/18/secureclaw-open-source-security-plugin-skill-openclaw/)  
- [Adversa AI: SecureClaw framework mapping](https://adversa.ai/blog/secureclaw-open-source-ai-agent-security-for-openclaw-aligned-with-owasp-mitre-frameworks/)  
- [Snyk agent-scan / mcp-scan (GitHub)](https://github.com/snyk/agent-scan)  
- [Cisco Skill Scanner (GitHub)](https://github.com/cisco-ai-defense/skill-scanner)  
- [AgentSec (GitHub)](https://github.com/debu-sinha/agentsec)

### Frameworks

- [OWASP Agentic Security Initiative (ASI) Top 10](https://owasp.org/www-project-agentic-security-initiative/)  
- [MITRE ATLAS Agentic AI TTPs](https://atlas.mitre.org/)

---

*agent-security-scanner-mcp — 6-Week Execution Plan* *February 18, 2026* *"Lead with research. Ship the scanner. Become the default."*  
