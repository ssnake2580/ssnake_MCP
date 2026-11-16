# Severity Guide

This project allows exactly four `level:` values: `low`, `medium`, `high`, `critical`.
Sigma's own `informational` is not accepted — every rule earns at least a `low`, or it
shouldn't be a detection rule at all (consider a hunting query instead).

Every rule must also justify its level choice in `description:` (see standard #2 in
`SKILL.md`), not just set the field. The guidance below is what that justification
should reason about.

## The core question

For each level, ask: **if this fires once, on its own, with no other context, how
confident am I that it represents malicious or at least policy-violating activity, and
how urgent is the response?**

## low

Evidence that is suggestive but common in benign activity, or evidence that only
matters in volume/pattern rather than as a single event.

- Fires often in normal admin/IT activity.
- Needs correlation with other events to mean much on its own.
- A single hit is worth logging and searching, not paging anyone.

Example: a scheduled task being created (T1053.005) — extremely common,
legitimately, across any fleet; only suspicious in combination with an unusual
binary path, creator, or timing.

## medium

A specific, somewhat uncommon technique or tool use that has real legitimate uses but
also real attacker use — worth a human look, not worth an incident.

- Legitimate use exists and is documented in `falsepositives:`, but it's the
  exception, not the rule.
- Often policy/hygiene signals: something that *shouldn't* be happening routinely,
  even if it isn't proof of compromise by itself.
- A single hit should be triaged, typically within the same business day.

Example: an application using the ROPC OAuth flow (T1078) — legitimate for legacy
apps, but exposes user passwords to the app directly and bypasses MFA; worth a
look, not an automatic incident.

## high

Strong, fairly specific evidence of a known attacker technique, with narrow
legitimate use.

- Few plausible non-malicious explanations; the ones that exist are named and
  specific in `falsepositives:` (e.g. "EDR agent X", not "could be anything").
- Represents a step that matters on its own (credential access, defense evasion,
  lateral movement primitive) even if it doesn't by itself prove full compromise.
- Should be triaged promptly (same-shift, not same-week).

Example: a process opening a handle to `lsass.exe` with a memory-read-capable
access mask (T1003.001) — opening the handle doesn't prove credentials were
successfully extracted, but there is very little legitimate reason for most
processes to do this.

## critical

Near-certain evidence of successful compromise, or of an action with severe,
often irreversible impact if real.

- Essentially no legitimate explanation, or the legitimate explanation is itself an
  emergency (e.g. a real ransomware recovery drill).
- Represents completed impact, not just an attempt: successful credential dumping
  tool execution with a confirmed dump file written, ransomware-note file drops,
  confirmed C2 beacon check-in, domain admin group modified by an unexpected actor.
- Should page someone immediately.

Example: `comsvcs.dll`'s `MiniDump` export being invoked against `lsass.exe` by
name from the command line — a narrow, well-documented, almost exclusively
malicious pattern with a completed action (the dump file), not just an attempt.

## Choosing between two adjacent levels

When torn between two levels, prefer the lower one and let `falsepositives:`
carry the nuance — an inflated severity that pages someone for a routine false
positive erodes trust in every rule that fires afterward. Write the description's
justification as a comparison: "not X because Y, not Z because W" (see the two
examples above) so a reviewer can evaluate the reasoning, not just the label.
