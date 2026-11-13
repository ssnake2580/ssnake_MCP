# Datasets

Spoor's accuracy is measured against a **public DFIR case with a published answer
key**, so findings are gradeable and the demo is reproducible. **No evidence images
or malware are committed** — only fetch instructions, hashes, and our *derived*
ground truth.

## Primary — DFIR Madness, Case 001: "The Stolen Szechuan Sauce"

| | |
|---|---|
| **Source** | https://dfirmadness.com/the-stolen-szechuan-sauce/ |
| **Answer key** | https://dfirmadness.com/answers-to-szechuan-case-001/ |
| **Evidence** | Windows **memory** + **E01 disk** + pagefile + **PCAP**, across two hosts |
| **Hosts** | `DC01` (Win Server 2012 R2, Domain Controller, `10.42.85.10`) · `DESKTOP-SDN1RPT` (Win 10) |
| **License** | Free/public for research. Redistribution terms unconfirmed → we ship **only our derived ground truth + this link**, never the images. |

### The known "evil" (ground truth)
- External attacker **`194.61.24.102`** brute-forces `Administrator` on **DC01** via **Hydra** (RDP).
- Malware **`C:\Windows\System32\coreupdate.exe`** downloaded over **HTTP @ 02:24:06**.
- Exfil archives **`secret.zip` @ ~02:31** and **`loot.zip` @ ~02:48**.

Machine-gradeable form: [`case001_ground_truth.json`](./case001_ground_truth.json). It is
derived from the published *narrative* answer key (fetched 2026-06-09) — **verify and
expand against the source before a final scored run.**

### Fetch (not committed)
```bash
# Archives live under https://dfirmadness.com/case001/ — e.g. the DC01 memory:
curl -L -O https://dfirmadness.com/case001/DC01-memory.zip
# verify against the PUBLISHED MD5 below, then extract READ-ONLY under
# $EVIDENCE_ROOT (e.g. evidence/case001/) and record the SHA256 (integrity baseline)
```

| Archive | URL | Published MD5 | SHA256 (computed on fetch) |
|---|---|---|---|
| DC01-memory.zip | https://dfirmadness.com/case001/DC01-memory.zip | `64A4E2CB47138084A5C2878066B2D7B1` ✓ verified 2026-06-10 | `86658d85d8254e8d30dccc4f50d9c2a8b550a101d2e78a6d932316849e37ad80` |
| DC01-E01.zip | https://dfirmadness.com/case001/DC01-E01.zip | `E57FC636E833C5F1AB58DFACE873BBDE` | _on fetch_ |
| DC01-pagefile.zip | https://dfirmadness.com/case001/DC01-pagefile.zip | `964EEAF0009D08CC101DE4A83A4E5D23` | _on fetch_ |
| DESKTOP-E01.zip | https://dfirmadness.com/case001/DESKTOP-E01.zip | `71C5C3509331F472ABCDF81EB6EFFF07` | _on fetch_ |
| DESKTOP-SDN1RPT-memory.zip | https://dfirmadness.com/case001/DESKTOP-SDN1RPT-memory.zip | `CF31E2635C77811AAA1BB04A92A721E2` | _on fetch_ |
| case001-pcap.zip | https://dfirmadness.com/case001/case001-pcap.zip | `422046B753CF8A4DF49D2C4CE892DB16` | _on fetch_ |

### Grading scope
`case001_ground_truth.json` is the canonical, full-case answer key (v1.0, verified
against the source on 2026-06-10; IOCs carry `host` + `evidence` scoping). A
**memory-only DC01 run** is graded against the derived subset
[`case001_ground_truth_dc01_memory.json`](./case001_ground_truth_dc01_memory.json)
so recall isn't penalized for artifacts only observable on the workstation's disk.

## Fallback (zero-friction)
A public Volatility 3 sample memory image
(<https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>) for the
memory-only path, if the full case is unavailable.
