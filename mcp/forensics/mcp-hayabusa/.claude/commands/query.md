---
description: Run a Hayabusa EVTX scan from a saved parameters file and write an Obsidian-style investigation note
argument-hint: <params-file> [time-range]
---

# Query — EVTX investigation from saved parameters

**This command runs against real Hayabusa scan data via the `scan_evtx` MCP tool. It does not use
Splunk or any SIEM.** This project has no SIEM access — this command adapts the familiar
"read a saved query from a file, run it, write up findings" workflow to the data we actually have:
local `.evtx` files scanned with Hayabusa. Do not suggest or fall back to Splunk syntax (`index=`,
`SPL`, etc.) anywhere in this command.

## Arguments

`$1` — required. Path to a plain-text parameters file (see format below).
`$2` — optional. A time range to scope the analysis to, e.g. `2026-07-10..2026-07-15` or
`last 24h`. **`scan_evtx` has no native time-range flag** — Hayabusa itself supports `-s`/`-e`
timeline bounds, but this project's wrapper doesn't expose them (see `src/mcp_hayabusa/hayabusa.py`).
So: if `$2` is given, run the scan unbounded as usual, then filter/annotate the *analysis* step by
each record's `Timestamp` field to stay inside that range — don't try to pass a time flag to the
tool. If `$2` is omitted, skip time-scoping entirely; don't invent a default window.

## Steps

1. **Read the parameters file** at `$1` with the Read tool. Expect simple `key: value` lines, e.g.:

   ```
   target: sample_evtx/Discovery/T1082_uname/uname.evtx
   rule_filter: discovery
   min_level: medium
   rules_dir: hayabusa/rules
   ```

   Required: `target` (path to a `.evtx` file or a directory of them — set `is_file: true` when
   calling the tool if `target` is a single file). Optional: `rule_filter`, `min_level`
   (`informational`/`low`/`medium`/`high`/`critical`), `rules_dir` (which rule set to scan/filter
   from — use `hayabusa/rules` for the full bundled Hayabusa Sigma ruleset, fetched via
   `scripts/download_hayabusa.py` and gitignored; omit it, or use `rules/custom`, to scan only this
   repo's own authored rules tracked in git). Ignore any other keys but don't error on them. If
   `target` is missing or doesn't resolve to an existing path, stop and report that — don't guess a
   path.

2. **Run the scan** with the `scan_evtx` MCP tool, passing `target`/`is_file`/`rule_filter`/
   `min_level`/`rules_dir` straight through from the file. Use `result_detail: "full"` if you need every
   matched record for the analysis in step 3; `"summary"` is enough if the level/rule-title counts
   alone answer the investigation. If the tool returns `{"error": ...}`, stop and surface that
   error verbatim rather than fabricating results.

3. **Analyze the results for suspicious patterns**: look at the level distribution, which rule
   titles fired most, any high/critical hits, and any records that cluster in time or around a
   specific host/user/process (whatever fields the matched records expose). If `$2` was given,
   note which findings fall inside vs. outside that range.

4. **Map findings to ATT&CK techniques.** For each distinct rule title in the results, look up its
   technique: call `get_hayabusa_rules` with a `filter_keyword` matching the rule title (or the
   `rule_filter` you used) to get technique tags, or read the `hayabusa://attack/{technique_id}`
   resource if you already have a candidate technique ID from the rule tags. Build a de-duplicated
   list of `attack.tXXXX`/`attack.tXXXX.XXX` IDs found across the fired rules.

5. **Check detection coverage.** For each technique ID found in step 4, read the
   `hayabusa://attack/{technique_id}` resource. Unlike `scan_evtx`/`get_hayabusa_rules`, this
   resource has no `rules_dir` parameter — it always resolves against this repo's own default
   rules directory (`./rules`, i.e. `rules/custom`), never `hayabusa/rules`. That's deliberate here:
   it answers "do *we* have our own authored/vetted detection for this technique" rather than "did
   the bundled third-party ruleset fire on it" — the scan itself may well have used
   `rules_dir: hayabusa/rules` and found the technique via a bundled rule, which is a different
   question from whether it's covered by a rule this repo tracks in git.
   - If the resource returns one or more rules: status **Covered**, and record the filename
     (basename of `path`, e.g. `lsass_memory_dump_via_comsvcs_minidump.yml`) of a matching rule.
   - If it returns no rules: status **Gap**.

6. **Generate an Obsidian-compatible markdown note** with:
   - YAML frontmatter: `date` (today, ISO), `tags` (e.g. `investigation`, plus one tag per
     technique like `T1003.001`), `techniques` (the list from step 4).
   - A `[[T1003.001]]`-style backlink for every technique found (as its own line or inline in the
     summary — Obsidian resolves these as note links, so use the bare technique ID, not a URL).
   - A findings summary in prose: what fired, what's notable, severity breakdown.
   - A "Detection Coverage" table from step 5, one row per technique found in step 4:

     ```
     | Technique | Status | Rule |
     |-----------|--------|------|
     | [[T1003.001]] | Covered | `lsass_memory_access.yml` |
     | [[T1550.002]] | Gap | No rule found |
     ```

   - A "Scan parameters" section showing the raw contents of `$1` (and `$2` if given) verbatim, plus
     the total record count and level counts from the `ScanResult`.
   - An "Analyst notes" section — leave this as an empty/placeholder section (e.g. a single `_TBD_`
     line) for a human to fill in; don't invent analyst commentary.

7. **Save the note** under `investigations/` at the repo root (create the directory if it doesn't
   exist). Name the file `investigations/<YYYY-MM-DD>-<slug-from-params-filename>.md`, e.g.
   `investigations/2026-07-18-uname-discovery.md`. Report the saved path back to the user.

## Notes

- Don't invoke the real `hayabusa` binary directly via Bash — always go through the `scan_evtx` /
  `get_hayabusa_rules` MCP tools, consistent with how the rest of this project uses Hayabusa.
- If `get_hayabusa_rules` or the ATT&CK resources return no technique for a fired rule, say so in
  the note rather than omitting the rule or guessing a technique ID.
- A "Gap" in the Detection Coverage table does not mean the technique went undetected in this scan
  — it means this repo has no rule of its own (under `rules/custom`) for it, even though a bundled
  rule (under `hayabusa/rules`) may have fired. Don't conflate the two in the findings summary.
