---
name: detection-engineering
description: Use this skill whenever writing or creating Sigma detection rules, reviewing existing detection rules, discussing detection coverage (e.g. "what ATT&CK techniques do we cover", gaps analysis), or working with YAML files under a rules/ or detections/ directory. Enforces this project's detection rule standards before a rule is considered complete or a review is considered passed. Triggers on: "sigma rule", "detection rule", "write a rule for", "review this rule", "detection coverage", "false positives", ".yml detection".
---

# Detection Engineering Standards

Every Sigma rule authored or reviewed under this skill must satisfy all five standards below.
Treat a rule that fails any of them as **not done** — do not present it as finished, and flag
every violation when reviewing someone else's rule.

## The five standards

### 1. ATT&CK technique mapping
The rule's `tags:` list must include at least one tag in `attack.tXXXX` (or `attack.tXXXX.XXX`
for a sub-technique) format, e.g. `attack.t1003.001`. A rule with no technique tag has no place
in the ATT&CK-indexed view of the rule set and must be rejected or sent back for mapping.

- Check: at least one tag matches `^attack\.t\d{4}(\.\d{3})?$` (case-insensitive).
- If the behavior genuinely doesn't map to a technique, that's a signal the rule may be too
  broad or mis-scoped — don't tag a placeholder technique just to satisfy the check.

### 2. Severity with justification
`level:` must be exactly one of: `low`, `medium`, `high`, `critical`. No other value (including
Sigma's own `informational`) is acceptable in this project.

- The rule must also carry a short justification for *why* that level was chosen — put it in
  `description:` (e.g. "high: direct evidence of credential dumping via LSASS access, low
  benign rate") rather than leaving the level as an unexplained bare enum value.
- Reject a rule whose description doesn't explain the severity choice, even if the `level:`
  field itself is valid.

### 3. Documented false positive conditions
`falsepositives:` must be a real, specific list — not empty, not `["Unknown"]`, not `["None"]`
used as a lazy default. Each entry should describe a concrete condition or tool that would
legitimately trigger the rule (e.g. "Administrative use of PsExec for patch deployment", "Backup
software performing volume shadow copy operations").

- A rule claiming zero false positives needs that claim justified in the description, not just
  an empty list.

### 4. At least one test case
Every rule needs at least one accompanying test case demonstrating it fires on real or
synthetic matching data. In this repo that means a sample `.evtx` (or exported record) under
`sample_evtx/` — or an equivalent fixture — plus a note (in the rule's `references:` or a
sibling test) of what sample log/record it was validated against and what the expected match is.

- A rule with detection logic but no evidence it was ever run against matching data is
  unverified, not tested — flag it accordingly.

### 5. Naming convention
Rule `title:` (as used for the filename and, where applicable, the `id`-adjacent human name)
must be lowercase with underscores instead of spaces or hyphens, e.g. `lsass_memory_dump_via_procdump`
rather than `LSASS Memory Dump via ProcDump` or `lsass-memory-dump-via-procdump`.

- Check: matches `^[a-z0-9]+(_[a-z0-9]+)*$`.
- This applies to the rule filename; the human-readable Sigma `title:` field itself may stay
  natural-language — don't force-lowercase a field meant for display. Apply the underscore
  convention to filenames and any internal rule-name identifiers.

## When writing a new rule

Don't hand back a rule missing any of the five items above and call it done. Walk through the
checklist explicitly before presenting the rule:

1. Technique tag(s) present and correctly formatted.
2. `level:` is one of the four allowed values, and `description:` explains the choice.
3. `falsepositives:` lists specific, real conditions.
4. A test case (sample log + expected match) exists or is proposed alongside the rule.
5. Filename is `lowercase_with_underscores.yml`.

## When reviewing a rule

Go through the same five checks and report every violation found — don't stop at the first one.
For each violation, state which standard it breaks and what's missing (e.g. "no attack.tXXXX tag
found in tags:" or "falsepositives is empty — needs at least one concrete condition"). A rule
that passes all five is clean; anything less needs to go back before being merged or loaded.

## References

- [`references/example-rules/lsass_memory_access.yml`](references/example-rules/lsass_memory_access.yml)
  — a rule satisfying all five standards above, with test evidence actually verified against a
  real sample under `sample_evtx/`. Use it as a template for formatting and for what a real
  (not placeholder) `falsepositives:`/test-evidence entry looks like.
- [`references/severity-guide.md`](references/severity-guide.md) — what distinguishes `low` from
  `medium` from `high` from `critical`, with worked examples, for justifying standard #2's
  `level:` choice.
- [`references/false-positive-patterns.md`](references/false-positive-patterns.md) — a catalog of
  recurring FP sources (EDR agents, admin tooling, backup software, legacy auth flows, dev/test
  activity, installers) to adapt when writing standard #3's `falsepositives:` list.
- Also usable directly: [`scripts/validate-rule.py`](scripts/validate-rule.py) — a CLI that checks
  a rule YAML against standards #1–#4 (tags, level, falsepositives, test-case evidence) and prints
  a JSON pass/fail report (`python scripts/validate-rule.py <path-to-rule.yml>`).
