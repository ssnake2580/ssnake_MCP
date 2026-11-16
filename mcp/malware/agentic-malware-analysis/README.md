# Agentic Malware Analysis

Automated deep malware reverse engineering driven by AI agents. A Kali-based Docker environment pairs 50+ RE tools with MCP-connected disassembler backends ([Binary Ninja][binary-ninja-headless-mcp] or [Ghidra][ghidra-headless-mcp]) and a structured multi-phase orchestrator skill that turns a raw binary into a case directory of ranked evidence, validated hypotheses, component maps, and a prioritized deep-analysis plan -- with no human interaction required. Ready for [Claude Code][claude-code] and [Codex CLI][codex-cli].

See the companion blog post [Building a Pipeline for Agentic Malware Analysis][blog-post] for background, a case study, and evaluation.

## Why

Initial malware analysis involves a number of routine steps: collecting hashes and compiler artifacts, extracting strings, inspecting imports, running YARA and capa, correlating the results, and identifying code areas for closer inspection. These steps provide the basis for deeper analysis, but they are often repetitive and time-consuming.

This repository automates much of that workflow. The orchestrator skill collects and organizes analysis artifacts, highlights relevant signals, generates evidence-backed hypotheses, builds a basic component model, and prepares a prioritized deep-analysis plan. All intermediate results are stored in a per-sample case directory on disk, making the workflow easier to resume and review.

Via MCP, the agent can also use Binary Ninja or Ghidra to inspect functions, follow cross-references, and tie findings to concrete code locations. The result is a structured starting point for follow-up analysis rather than ad hoc triage alone.

## Features

- Kali Linux container with 50+ RE and malware analysis tools
- Automatic MCP backend selection (Binary Ninja or Ghidra)
- `malware-analysis-orchestrator` skill for Claude Code and Codex CLI
- Helper scripts for strings, imports, YARA, capa, signal ranking, hypothesis generation
- Bundled YARA rules (crypto, anti-debug/anti-VM, capabilities, packer -- from [Yara-Rules/rules][yara-rules], GPL-2.0)
- Wrapper scripts for Claude Code and Codex with aggressive defaults
- Persistent state across container rebuilds (BN license, Claude auth, Codex auth)
- PE, ELF, and Mach-O support
- Content-hash-based image caching

## Prerequisites

- Docker with `buildx`
- Anthropic API key or Claude account (for Claude Code) or OpenAI API key (for Codex)
- Recommended: Binary Ninja Linux zip with a headless-capable license (see [Setup](#setup) below)

## Quick Start

> **Important:** `run_docker.sh` mounts your current working directory into the container at `/agent`. The agent wrappers run with full permissions (`--dangerously-skip-permissions` / `--dangerously-bypass-approvals-and-sandbox`) by design, so the agent can read, write, and execute anything in that directory. Clone the repository into a dedicated directory and place only the files you want the agent to access there.

```bash
git clone https://github.com/mrphrazer/agentic-malware-analysis.git
cd agentic-malware-analysis
cp /path/to/binaryninja_linux.zip ./binaryninja.zip   # recommended; without it Ghidra is used instead
./run_docker.sh
```

What happens:

1. Prepares a Docker Buildx builder
2. If `binaryninja.zip` is present, Binary Ninja and its MCP server are installed; otherwise Ghidra and its MCP server are installed as a fallback
3. Clones the selected MCP server repo into `mcp/`
4. Builds the image (or reuses a cached one based on content hash)
5. Seeds BN license, Claude credentials, and Codex credentials from host directories
6. Launches the container with the current directory mounted at `/agent`

Inside the container:

```bash
claude   # or: codex
```

Extract the included example sample and start an analysis with the orchestrator skill:

```bash
cd examples && unzip -P infected samples.zip && cd ..
```

Then prompt the agent:

```
Analyze the malware in examples/samples/mfc42ul.dll -- Give me a detailed overview
of the sample's functionality and features, together with the corresponding code
locations. Use the skill /agent/agent_helpers/claude/skills/malware-analysis-orchestrator/
for analysis.
```

See [examples/README.md](examples/README.md) for sample details and background.

## Setup

### Binary Ninja (recommended)

Binary Ninja provides substantially better analysis results than Ghidra through its [headless MCP server][binary-ninja-headless-mcp] and is the recommended disassembler backend. If no Binary Ninja zip is present, the environment falls back to Ghidra automatically.

To use Binary Ninja, place your Linux headless zip in the repository root **before** running `run_docker.sh`:

```bash
cp /path/to/binaryninja_linux.zip ./binaryninja.zip
```

The file must be named `binaryninja.zip`. Alternatively, point to it explicitly:

```bash
BINARY_NINJA_ZIP=/path/to/binaryninja.zip ./run_docker.sh
```

Binary Ninja requires a valid `license.dat`. On first run, `run_docker.sh` copies your existing license from `~/.binaryninja/license.dat` into a Docker-specific directory (`~/.binaryninja-docker/`) that is mounted into the container at `/home/agent/.binaryninja`. The license is never baked into the image. To use a different host directory:

```bash
BINARY_NINJA_USER_DIR=/path/to/binaryninja-user-dir ./run_docker.sh
```

### Claude Code Authentication

`run_docker.sh` maintains a persistent Claude state directory at `~/.claude-docker/` on the host, mounted into the container at `/home/agent/.claude`. On first run, it seeds credentials from `~/.claude/.credentials.json` if available. You can also log in inside the container with `claude auth`; credentials persist across container rebuilds in the mounted directory. To use a different host directory:

```bash
CLAUDE_USER_DIR=/path/to/claude-dir ./run_docker.sh
```

### Codex CLI Authentication

`run_docker.sh` maintains a persistent Codex state directory at `~/.codex-docker/` on the host, mounted into the container at `/home/agent/.codex`. On first run, it seeds credentials from `~/.codex/auth.json` if available. You can also log in inside the container with `codex login`; credentials persist across container rebuilds in the mounted directory. To use a different host directory:

```bash
CODEX_USER_DIR=/path/to/codex-dir ./run_docker.sh
```

## Docker Environment

### Installed Tooling

**Fingerprinting:** `file`, `sha256sum`, `md5sum`, `ssdeep`, `die`/`diec`, `yara`, `capa`

**String extraction:** `strings`, `floss` (FLARE-FLOSS), `rabin2`

**Disassembly and analysis:** `radare2`, `binwalk`, `gdb`/`gdb-multiarch`, `capstone` (Python)

**Binary utilities:** `objdump`, `readelf`, `nm`, `patchelf`, `elfutils`

**Hex editors:** `hexedit`, `bvi`, `xxd`, `ht`, `hexwalk`

**Dynamic analysis:** `strace`, `ltrace`, `qemu-user`

**Build tools:** `gcc`, `g++`, `clang`, `lldb`, `lld`, `llvm`, `cmake`, `nasm`

**Python:** Python 3, `pip`, `venv`, `ipython`, `ipdb`, `uv`

**Data processing:** `jq`, `yq`

**Extraction:** `upx`, `unblob`, `ropper`

**Node.js:** Node.js 22

**Agent CLIs:** Claude Code, Codex CLI

**Conditional:** Binary Ninja headless + Python API (if zip provided) _or_ Ghidra + `pyghidra`

### Runtime Configuration

- Working directory: `/agent`
- User: `agent` (non-root, passwordless sudo)
- Capabilities: `SYS_PTRACE`, `seccomp=unconfined`
- Volume mounts:
  - Host `.` → `/agent`
  - BN user dir → `/home/agent/.binaryninja`
  - Claude state dir → `/home/agent/.claude`
  - Codex state dir → `/home/agent/.codex`

## MCP Integration

The environment automatically selects and configures one MCP backend. Binary Ninja is recommended; Ghidra serves as a fallback when no Binary Ninja zip is provided.

- **Binary Ninja installed** → [binary-ninja-headless-mcp][binary-ninja-headless-mcp] (registered as `binary_ninja_headless_mcp`)
- **No Binary Ninja** → [ghidra-headless-mcp][ghidra-headless-mcp] (registered as `ghidra_headless_mcp`)

The selected repo is cloned at runtime by `run_docker.sh` into `mcp/`. On container start, `configure-agent-mcp.sh` writes the project-scoped `.mcp.json` (Claude Code) and Codex config with the correct MCP server entry.

Override the upstream repos:

```bash
BINJA_MCP_REPO_URL=https://github.com/mrphrazer/binary-ninja-headless-mcp.git ./run_docker.sh
GHIDRA_MCP_REPO_URL=https://github.com/mrphrazer/ghidra-headless-mcp.git ./run_docker.sh
```

## Malware Analysis Orchestrator

The `malware-analysis-orchestrator` skill drives a structured, multi-phase malware analysis workflow. It is available for both [Claude Code](agent_helpers/claude/skills/malware-analysis-orchestrator/SKILL.md) and [Codex CLI](agent_helpers/codex/skills/malware-analysis-orchestrator/SKILL.md).

### Workflow Stages

1. **Intake and fingerprinting** -- hashes, file type, packer/compiler detection, YARA scan, capa scan
2. **Raw strings collection** -- `strings`, `rabin2`, `floss` with source tags
3. **Raw API/import collection** -- `rabin2`, format-specific tools (PE/ELF/Mach-O)
4. **Signal filtering and ranking** -- score and rank interesting strings and imports by capability
5. **Hypothesis generation** -- cross-link evidence, generate behavior hypotheses with confidence and evidence
6. **Component inventory and interaction modeling** -- infer components, map data/control flow
7. **Deep analysis planning and prioritization** -- ordered tasks with target functions, expected findings, stop criteria
8. **Reporting** -- executive summary, technical findings, IOCs, open questions

### Case Directory

Each analysis creates a persistent per-sample directory at `status/<NNN>-<filename>/` containing 13 required artifact files:

| # | File | Content |
|---|------|---------|
| 1 | `00_sample_profile.md` | Hashes, file type, packer, YARA, capa results |
| 2 | `01_strings_raw.txt` | All extracted strings with source tags |
| 3 | `02_strings_interesting.md` | Ranked interesting strings with categories |
| 4 | `03_imports_raw.txt` | Full import tables with source tags |
| 5 | `04_imports_interesting.md` | Suspicious API clusters by capability |
| 6 | `05_behavior_hypotheses.md` | Hypotheses with confidence and evidence |
| 7 | `06_component_inventory.md` | Inferred components with roles and evidence |
| 8 | `07_interaction_model.md` | Data and control flow between components |
| 9 | `08_deep_analysis_plan.md` | Ordered deep-analysis tasks |
| 10 | `09_priority_queue.md` | Priority queue with rationale and blockers |
| 11 | `10_reporting_draft.md` | Executive summary and technical findings |
| 12 | `INDEX.md` | Artifact list, timestamps, missing items |
| 13 | `CURRENT_STATE.json` | Machine-readable phase and progress state |

This externalized state is what makes the workflow resilient to context-window compaction: the agent reads case files back from disk instead of relying on conversation history.

### Helper Scripts

| Script | Purpose |
|--------|---------|
| `init_status_tree.sh` | Create or reuse a case directory for a sample |
| `collect_strings.sh` | Run `strings`, `rabin2 -zz`, `floss` and write raw output |
| `collect_imports.sh` | Run `rabin2 -i` and format-specific import tools |
| `scan_yara.sh` | Scan sample with bundled YARA rules |
| `scan_capa.sh` | Run capa for ATT&CK/MBC capability identification |
| `rank_signals.py` | Score and rank interesting strings and imports |
| `build_hypothesis.py` | Generate baseline behavior hypotheses (optional) |
| `update_state.py` | Update `CURRENT_STATE.json` with phase transitions |
| `resolve_case.sh` | Resolve the latest case directory for a sample |

### Bundled YARA Rules

Four rule sets from [Yara-Rules/rules][yara-rules] (GPL-2.0):

- `crypto_signatures.yar` -- cryptographic algorithm and constant detection
- `antidebug_antivm.yar` -- anti-debug and anti-VM technique detection
- `capabilities.yar` -- malicious capability detection
- `packer_compiler_signatures.yar` -- packer and compiler signature detection

### Roles

- **Orchestrator** -- drives phases, enforces artifact completeness, schedules parallel collection
- **Planner** -- consumes intermediate evidence, generates hypotheses, defines deep-analysis priorities
- **Reporter** -- produces executive and technical summaries with traceable evidence

## Agent Wrappers

### Claude Code

- Default model: `opus`
- Default effort: `high`
- Default permissions: `--dangerously-skip-permissions`
- Management commands (`auth`, `doctor`, `mcp`, `update`, etc.) are passed through without defaults
- See [Claude Code Authentication](#claude-code-authentication) for credential setup

### Codex CLI

- Default model: `gpt-5.4`
- Default reasoning: `xhigh`
- Default permissions: `--dangerously-bypass-approvals-and-sandbox`
- Features: `multi_agent`, `child_agents_md`
- Management commands (`login`, `logout`, `mcp`, `features`, etc.) are passed through without defaults
- See [Codex CLI Authentication](#codex-cli-authentication) for credential setup

## Customization

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `BINARY_NINJA_ZIP` | `./binaryninja.zip` | Path to Binary Ninja Linux zip |
| `BINARY_NINJA_USER_DIR` | `~/.binaryninja-docker` | BN license, settings, and plugins |
| `CLAUDE_USER_DIR` | `~/.claude-docker` | Claude auth and state |
| `CODEX_USER_DIR` | `~/.codex-docker` | Codex auth and state |
| `BINJA_MCP_REPO_URL` | `https://github.com/mrphrazer/binary-ninja-headless-mcp.git` | Binary Ninja MCP repo |
| `GHIDRA_MCP_REPO_URL` | `https://github.com/mrphrazer/ghidra-headless-mcp.git` | Ghidra MCP repo |

### Running Specific Commands

```bash
./run_docker.sh claude
./run_docker.sh codex
./run_docker.sh python3 -c 'import sys; print(sys.version)'
```

## Repository Layout

```
.
├── Dockerfile
├── compose.yaml
├── run_docker.sh
├── docker-bin/
│   ├── claude
│   ├── codex
│   └── configure-agent-mcp.sh
├── docker-config/
│   └── codex-config.toml
├── agent_helpers/
│   ├── claude/skills/malware-analysis-orchestrator/
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   ├── references/
│   │   └── assets/
│   │       ├── yara_rules/
│   │       └── status_templates/
│   └── codex/skills/malware-analysis-orchestrator/
│       ├── SKILL.md
│       ├── agents/
│       ├── scripts/
│       ├── references/
│       └── assets/
│           ├── yara_rules/
│           └── status_templates/
├── examples/
│   ├── README.md
│   └── samples.zip
├── blogs/
└── README.md
```

Note: `mcp/` is cloned at runtime and is not part of the repository.


## Limitations

- Agent runs are non-deterministic -- repeated analyses of the same sample may produce different results
- Context-window constraints limit single-pass depth; the orchestrator mitigates this with externalized state
- Agents may produce overconfident or incorrect claims -- expert validation is required
- The orchestrator focuses on static analysis; dynamic analysis tools are available but not orchestrated
- The container runs with elevated permissions by design (see Security)

## Security

- `SYS_PTRACE` and `seccomp=unconfined` are required for debugging and dynamic analysis -- intentional
- Agent wrappers default to full permissions inside the container sandbox -- by design for autonomous analysis
- MCP communication is unauthenticated (stdio transport)
- Do not expose the container to untrusted networks or users
- The Binary Ninja license is stored on the host, not in the image

## Contact

Tim Blazytko ([@mr_phrazer](https://x.com/mr_phrazer))

[binary-ninja-headless-mcp]: https://github.com/mrphrazer/binary-ninja-headless-mcp
[ghidra-headless-mcp]: https://github.com/mrphrazer/ghidra-headless-mcp
[claude-code]: https://docs.anthropic.com/en/docs/claude-code
[codex-cli]: https://github.com/openai/codex
[blog-post]: https://synthesis.to/2026/03/18/agentic_malware_analysis.html
[yara-rules]: https://github.com/Yara-Rules/rules
