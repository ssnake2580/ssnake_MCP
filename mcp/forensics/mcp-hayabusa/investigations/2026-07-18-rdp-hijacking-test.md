---
date: 2026-07-18
tags:
  - investigation
  - T1563.002
  - T1021.001
techniques:
  - T1563.002
  - T1021.001
---

# RDP session hijacking test scan — T1563.002 / T1021.001

[[T1563.002]]
[[T1021.001]]

## Findings summary

Scanning the Yamato Security RDP Hijacking sample (`T1563.002_RDP-Hijacking_Security.evtx`) with
the bundled Hayabusa Sigma ruleset filtered to `rdp`, at `medium`+ severity, produced 3 matched
records — all **medium** level, all EventID 4688 (process creation) on host `wef.windomain.local`:

- **Possible RDP Hijacking** (rule `6be7f3fc-8917-11ec-a8a3-0242ac120002`, tags
  `attack.t1563.002` + `attack.t1021.001`) — fired twice, once for
  `cmd.exe /k tscon 2 /dest rdp-tcp#14` (PID 6528, parent `services.exe`, running as `SYSTEM`) and
  once for the resulting `tscon.exe 2 /dest rdp-tcp#14` (PID 7052, parent `cmd.exe`). This is the
  textbook `tscon.exe`-based RDP session hijack: redirecting an existing disconnected session
  (session ID 2) onto a new RDP connection without the target's credentials, executed by the
  `WEF$` machine account at SYSTEM integrity.
- **Potential RDP Session Hijacking Activity** (rule `679db9c2-6669-dc7b-3b9c-a20f4d600b28`) —
  fired once, on the same `tscon.exe` record as above. This rule's tags are only
  `attack.execution` — **no specific ATT&CK technique ID is tagged on this rule**, only the
  generic Execution tactic, so it isn't included in the `techniques` list above despite being
  RDP-hijacking-relevant by title/description.

Both firing records cluster at the same timestamp (`2022-02-08 21:33:15`, ~7ms apart), consistent
with a single `cmd.exe` → `tscon.exe` execution chain rather than separate, unrelated events. No
high/critical hits. Severity breakdown: medium — 3, all other levels — 0.

## Scan parameters

`$1` (`queries/rdp-hijacking-test.txt`):

```
target: sample_evtx/YamatoSecurity/LateralMovement/T1563.002_RDP-Hijacking_Security.evtx
rule_filter: rdp
min_level: medium
rules_dir: hayabusa/rules
```

`$2` (time range): not given — analysis is not time-scoped.

- Total record count: 3
- Level counts: `{"med": 3}`

## Analyst notes

_TBD_
