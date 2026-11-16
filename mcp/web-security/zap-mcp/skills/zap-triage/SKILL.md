---
name: zap-triage
description: Triage ZAP alerts using the OWASP Risk Rating Methodology and write a clear security report. Use after zap_get_alerts, or when asked to triage, rate, or report on web security scan findings.
---

# ZAP triage and report

Turn raw ZAP alerts into a short report a developer can act on. Be honest about what was proven and what was not.

## 1. Gather

- Call `zap_get_alerts` (use `baseurl` to scope, `min_risk: "Informational"` if asked for everything).
- Note the target, the date, and **what was exercised** (pages and flows browsed). Passive scanning only sees traffic that went through the proxy; say so.

## 2. PoC or GTFO

A scanner alert is a hypothesis, not a finding. Before anything reaches the report, try to prove it against the target.

- Replay the request that triggered the alert (curl or the browser) and show the exact response that demonstrates the problem: the header that is missing, the value that leaks, the cross-origin read that succeeds.
- Keep proofs minimal and non-destructive: read-only requests, your own test account, no data modification, no more data than needed to show the issue exists. Only do this against targets the user owns or is authorised to test. If unsure, stop and ask.
- Classify each finding:
  - **Proven**: you reproduced it and have the request and response. It goes in the report.
  - **Not reproducible / noise**: it did not reproduce, or is true but irrelevant here (a missing header on a static asset, a timestamp that is just a timestamp). One line in the "Dismissed" list, nothing more.
  - **Unproven**: plausible, but you could not verify it safely. Say what a human should check. Never present it as confirmed.

No proof, no finding. The report is short because it is only what was shown to be real.

## 3. Rate with OWASP Risk Rating

Follow the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology). Rate **Likelihood** and **Impact** each as LOW (0 to <3), MEDIUM (3 to <6) or HIGH (6 to 9), using these factors:

- Likelihood, threat agent: skill level, motive, opportunity, population size.
- Likelihood, vulnerability: ease of discovery, ease of exploit, awareness, intrusion detection.
- Impact, technical: loss of confidentiality, integrity, availability, accountability.
- Impact, business: financial damage, reputation damage, non-compliance, privacy violation.

Overall severity:

| Likelihood \ Impact | LOW | MEDIUM | HIGH |
|---|---|---|---|
| HIGH | Medium | High | Critical |
| MEDIUM | Low | Medium | High |
| LOW | Note | Low | Medium |

Do not copy ZAP's own risk label. It rates the *type* of issue; you rate it *in this app's context*. Say when your rating differs and why. Estimate factors from what you saw; state assumptions instead of inventing precision. One-line justification per finding is enough.

## 4. Write the report

Use exactly this structure:

1. **Summary**: two or three sentences, the overall posture, and the one thing to fix first.
2. **Scope and limits**: target, date, flows covered, passive only, what was not tested.
3. **Findings**, ordered by severity. For each:
   - Title and OWASP severity (Likelihood / Impact)
   - Proof: the request you sent and the response that shows it (trimmed to the relevant lines)
   - Why it matters in this app, in plain language
   - Fix: a concrete change, not "improve security"
4. **Dismissed and unproven**: one line each with the reason.
5. **Next steps**: what to verify manually, and what an active scan or manual test should cover.

Rules: group duplicates, every finding has a proof, keep it under two pages, no scare language, no raw alert dumps.
