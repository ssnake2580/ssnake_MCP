---
name: zap-fix-loop
description: Full security loop for a coding agent working in the app's own repo: scan the running app with ZAP, prove each finding, fix it in code, verify the fix by replaying the proof, and prepare a pull request. Use when asked to find and fix web security issues in the project being worked on.
---

# Scan, prove, fix, verify

You are a teammate in the development flow, not an outside auditor. Do not hand over a list of problems; hand over fixes with proof that they work. Only run this against an app the user owns and is authorised to test, running locally or in a test environment.

## Loop

1. **Run it.** Start the app locally (use the project's own run instructions). Call `zap_start`. Note that ZAP runs in Docker, so reach a local app as `host.docker.internal`.
2. **Exercise it.** Drive a browser through the ZAP proxy over the flows that matter (sign-up, login, the main user journeys, anything the user named). Passive scanning only sees what you visit.
3. **Triage with proof.** Call `zap_get_alerts`, then follow the `zap-triage` rules: PoC or GTFO. Keep only findings you reproduced with a minimal, read-only request, and rate them with the OWASP Risk Rating Methodology. Drop the rest with a one-line reason.
4. **Fix, one finding at a time.** Work on a branch, highest severity first. Find the code responsible, make the smallest change that removes the cause (not a workaround that only silences the alert), and add a regression test where the project has a test setup.
5. **Verify.** Restart the app, replay the exact proof request, and confirm the response no longer shows the problem. Run the project's tests. If the proof still works, the fix is not done: iterate, or say you could not fix it.
6. **Re-scan.** Repeat the browsing flow and call `zap_get_alerts` again. Confirm the finding is gone and nothing new appeared.
7. **Stop and hand over.** Call `zap_stop`. Commit with one commit per finding. Do not push or open a pull request until the user says so, then open it with the summary below.

## Pull request summary

For each finding: severity (Likelihood / Impact), the proof before (request and response), the change, and the proof after. Then a short list of what was dismissed or left unproven, and what was not covered by the browsing.

## Guardrails

- Never run against production or third-party systems. If the target is not clearly local or a test environment, stop and ask.
- Read-only proofs, your own test account, no data modification.
- Do not weaken security controls, disable checks, or suppress alerts to get a clean scan.
- If a fix needs a design decision (auth model, CORS policy for real clients), propose the options and ask instead of guessing.
