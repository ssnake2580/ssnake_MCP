# False Positive Patterns

`falsepositives:` must list specific, real conditions (standard #3 in `SKILL.md`) — never
left empty, and never just `["Unknown"]` or `["None"]` as a lazy default. This is a
catalog of the FP sources that recur across Windows detection rules, to make writing a
specific list faster than inventing one from scratch each time. Treat these as starting
points to adapt to the rule's exact logic, not as copy-pasteable text — a false positive
entry should name the actual tool/process/condition, not a category.

## Security tooling and EDR agents

Endpoint agents legitimately do things that look identical to attacker behavior, because
they're built to inspect the same surfaces attackers abuse.

- AV/EDR engines opening handles to `lsass.exe` for credential-theft *detection* (e.g.
  Microsoft Defender's `MsMpEng.exe`, MDE's `MsSense.exe`/`SenseIR.exe`) — the same
  process-access pattern as an actual LSASS dump attempt.
- Vulnerability scanners and asset-inventory agents enumerating installed software,
  services, or scheduled tasks at regular intervals.
- DLP/CASB agents inspecting file contents or clipboard activity for policy enforcement.

Document by naming the specific product/process image where known — "an unspecified EDR
agent" is not a usable falsepositives entry; "MsSense.exe (Microsoft Defender for
Endpoint sensor)" is.

## Legitimate admin tooling

Tools that are dual-use by design: built for IT operations, also popular with attackers
because they're already trusted and often allowlisted.

- PsExec and other Sysinternals tools used for patch deployment or remote
  troubleshooting.
- PowerShell remoting (WinRM) for routine fleet management.
- RDP/admin share access from designated jump hosts or bastion systems.
- WMI used by legitimate configuration-management platforms (SCCM, Intune, Ansible).

Document the *legitimate context*, not just the tool name — "PsExec" alone doesn't
distinguish an admin from an attacker; "PsExec launched from the patch-management jump
host during a scheduled maintenance window" does.

## Backup, imaging, and recovery software

Backup agents routinely need broad filesystem/process access that mimics
destructive or credential-access behavior.

- Volume Shadow Copy Service (VSS) operations during scheduled backup jobs.
- Backup agents opening handles to running processes (including `lsass.exe`) to
  capture consistent snapshots.
- Imaging/cloning tools reading raw disk sectors.

## Legacy and non-standard authentication flows

Older or simplified auth flows that predate (or deliberately bypass) modern
protections, still legitimately used by legacy apps or during migrations.

- ROPC (resource owner password credentials) OAuth flow used by legacy
  line-of-business apps that can't be updated to a modern flow.
- Basic auth against on-prem services during a phased migration to modern auth.
- Service accounts with non-expiring passwords used by scheduled batch jobs.

## Developer and automated-testing activity

Behavior that's suspicious in production but routine in dev/test environments.

- Automated test suites that exercise the exact auth flow or API surface a rule
  targets (e.g. ROPC used by CI credential-testing jobs, not just legacy apps).
- Debuggers/profilers attaching to processes during development.
- CI/CD runners executing scripted, unattended logins.

## Software installers and updaters

Legitimate software delivery mechanisms that resemble living-off-the-land binary
(LOLBin) abuse.

- `rundll32.exe`/`regsvr32.exe` invoked by installers registering COM components
  or DLLs as part of normal software setup.
- MSI-based installers spawning `msiexec.exe` with elevated privileges.
- Auto-update mechanisms downloading and executing signed binaries outside the
  usual install directory.

## Writing the entry

A good `falsepositives:` entry answers three things: **who** (which tool, process, or
role), **why** (what legitimate task they're doing), and **how it's distinguishable**
from the malicious case if it is (e.g. process image, source host, timing). If a rule
genuinely has no known false positives, that claim itself needs justification in
`description:` — explain why the detection logic is narrow enough to rule out the
categories above, rather than leaving `falsepositives:` looking like it was never
considered.
