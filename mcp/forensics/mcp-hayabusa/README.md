# mcp-hayabusa

[![Tests](https://github.com/msadigo/mcp-hayabusa/actions/workflows/tests.yml/badge.svg)](https://github.com/msadigo/mcp-hayabusa/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa),
the Windows event log fast forensics timeline and threat-hunting tool, so an
MCP client (e.g. Claude Code) can run detection scans over `.evtx` files.

## Prerequisites

- Python 3.10+
- The `hayabusa` binary, downloaded from the
  [Hayabusa releases page](https://github.com/Yamato-Security/hayabusa/releases)
  (or built from source), available on `PATH`, or pointed to via the
  `HAYABUSA_BIN` environment variable.

  `scripts/download_hayabusa.py` will fetch the latest release for your
  platform and extract it to `./hayabusa/`:

  ```sh
  python scripts/download_hayabusa.py
  # then either add ./hayabusa to PATH, or:
  export HAYABUSA_BIN=./hayabusa/hayabusa   # ./hayabusa/hayabusa.exe on Windows
  ```

  Pass `--version vX.Y.Z` to pin a release, `--musl` for a musl build on
  Linux, or `--force` to re-download.

## Install

```sh
pip install -e .
```

## Run

```sh
mcp-hayabusa
```

Or point an MCP client's config at the installed console script
(`mcp-hayabusa`) or at `python -m mcp_hayabusa.server`.

## Configuration

| Env var       | Purpose                                                              |
|---------------|-----------------------------------------------------------------------|
| `HAYABUSA_BIN`| Full path (or PATH-resolvable name) of the hayabusa binary to invoke. |

Copy `.env.example` to `.env` and fill it in as a reference for what to set. Nothing auto-loads
`.env`: export the variables yourself (or use a tool like `direnv`) before running `mcp-hayabusa`/
`mcp dev`/`mcp run`, or, if installing into the Claude Desktop app, pass it straight to
`mcp install src/mcp_hayabusa/server.py --env-file .env`.

## Tools

### `scan_evtx`

Runs `hayabusa csv-timeline` or `hayabusa json-timeline` against a single
`.evtx` file or a directory of `.evtx` files, always non-interactively.

Parameters: `target`, `is_file`, `output_format` (`csv`/`json`/`jsonl`),
`rules_dir`, `min_level`, `utc`, `output_path`.

Returns the command that was run, exit code, a preview of up to 20 result
records, the total record count, and truncated stdout/stderr. Pass
`output_path` explicitly to keep the full result file on disk; otherwise a
temporary file is used and removed after the preview is extracted.

### `get_hayabusa_rules`

Lists Hayabusa/Sigma detection rules, optionally filtered by keyword — useful
for browsing/searching what's available before running `scan_evtx` with a
`rule_filter`, since both use the same case-insensitive text match.

Parameters: `keyword`, `rules_dir`, `max_results`.

Returns `total_matched` (true count) and up to `max_results` rules, each with
`path`, `id`, `title`, `level`, `status`, `description`, `author`, `tags`, and
`logsource`.

## Resources

A read-only, browsable detection knowledge base — Sigma rules and their
ATT&CK mappings — for a client to navigate directly instead of only through
tool calls.

| URI                             | Kind     | Description                                                                 |
|----------------------------------|----------|------------------------------------------------------------------------------|
| `hayabusa://attack`               | static   | Every ATT&CK technique ID present in the loaded rule set, with a rule count each. |
| `hayabusa://attack/{technique_id}`| template | Rules tagged with one technique, e.g. `hayabusa://attack/T1003` (case-insensitive). |
| `hayabusa://rules/{path}`         | template | Raw Sigma rule YAML (including its `detection:` logic) for one rule file.  |

`path` in `hayabusa://rules/{path}` is a rule's `path` field from
`get_hayabusa_rules` or an ATT&CK resource, with every `/` percent-encoded
(`%2F`) — MCP resource URI templates only match a single path segment.
