---
date: 2026-07-18
tags:
  - investigation
  - T1558.003
techniques:
  - T1558.003
---

# Kerberoasting test scan — T1558.003

[[T1558.003]]

## Findings summary

Scanning the Yamato Security Kerberoasting sample (`T1558.003_StealOrForgeKerberosTicketsKerberoasting_Security.evtx`)
with the bundled Hayabusa Sigma ruleset filtered to `kerberoast`, filtered to `medium`+ severity,
produced 2 matched records, both at **medium** level and both against the same underlying event
(EventID 4769, RecordID 38681, timestamp `2021-04-29 10:23:58.726 +01:00`, host
`DC-Server-1.labcorp.local`):

- **Possible Kerberoasting (RC4 Kerberos Ticket Req)** (rule `f19849e7-b5ba-404b-a731-9b624d7f6d19`) —
  fires on a Kerberos TGS request using RC4 ticket encryption (`TicketEncryptionType: 0x17`), a
  classic Kerberoasting indicator since RC4-encrypted service tickets are the ones commonly cracked
  offline.
- **Kerberoasting Activity - Initial Query** (rule `4386b4e0-f268-42a6-b91d-e3bb768976d6`) — a
  broader collector rule flagging TGS requests worth correlating for a burst-of-requests pattern
  (the rule's own description notes it needs follow-up analysis across multiple service names in a
  tight time window to become a firm alert).

Both records show the same actor/target pair: requester `Alice@LABCORP.LOCAL`, requested service
`sql101`, source IP `::ffff:192.168.1.200`, ticket status `0x0` (success). Only one event fired both
rules — there's no burst of distinct service requests in this sample, so the "Initial Query" rule's
own recommended follow-up (multiple SPNs requested from one host within ~5 seconds) can't be
confirmed from this single-file scan; it would need a directory scan across a wider log set to
evaluate that pattern.

No high/critical hits and no other rule titles fired. Severity breakdown: medium — 2, all other
levels — 0.

## Detection Coverage

| Technique | Status | Rule |
|-----------|--------|------|
| [[T1558.003]] | Gap | No rule found |

This scan's hits came entirely from the bundled Hayabusa ruleset (`rules_dir: hayabusa/rules`).
This repo's own custom rules (`rules/custom/`, tracked in git) have no rule tagged
`attack.t1558.003` — so despite being detected here, Kerberoasting is a gap in this project's own
authored detection coverage, not just an unfired technique.

## Scan parameters

`$1` (`queries/kerberoasting-test.txt`):

```
target: sample_evtx/YamatoSecurity/CredentialAccess/T1558.003_StealOrForgeKerberosTicketsKerberoasting_Security.evtx
rule_filter: kerberoast
min_level: medium
rules_dir: hayabusa/rules
```

`$2` (time range): not given — analysis is not time-scoped.

- Total record count: 2
- Level counts: `{"med": 2}`

## Analyst notes

_TBD_
