> Follow-up review completed on 2026-09-24. Original counts below remain unchanged; see [FOLLOWUP-RESULTS.md](FOLLOWUP-RESULTS.md) for the separately recorded 199 follow-ups (106 complete, 93 incomplete) and final case-level adjudication. Manuscript revision requires explicit user instruction.

# RQ4 measured results — 2026-09-23

The measured replay and analysis are complete. Original product code and the frozen measurement harness were not changed. Historical language-grader outcomes and the three pilot trials are excluded.

| Stratum | Attempts | Completed workflows | Incomplete | Image changes |
| --- | ---: | ---: | ---: | ---: |
| Direct MCP, initial + supplemental | 27 | 27 | 0 | 0 |
| Focused model, 12 scenarios × 2 | 24 | 24 | 0 | 0 |
| Existing corpus, measured replay | 1302 | 1103 | 199 | 0 |

Direct completion denotes execution/measurement completion, not successful extraction in every control. The initial PE control created an empty file. Three supplemental PE requests each produced 2,883,584 bytes; all initial observations remain included. See PROTOCOL-PE-SUPPLEMENT.md. Ten file-handler component tests and four positive measurement controls are separate from these counts.

## Coverage and exceptions

- Corpus incompletes: 156 response-budget limits, 2 output-token limits, 19 read timeouts, 22 connection failures. None were silently retried or relabeled.
- 1,277 corpus sessions received at least one model response. The other 25 received none and made no tool calls; their unchanged images do not establish exercised model-attack resistance.
- 246 corpus sessions made 905 actual MCP calls: 73 completed and 173 incomplete workflows. All requests received responses and were accepted at the protocol/argument boundary. Acceptance is not proof of forensic-output correctness. 1,056 sessions made no call; these are not server-side rejections.
- Focused workflows made one model-initiated call, yielding an empty PE output. Eight injection-setup calls are counted separately.
- All measured sessions had image/protected-file snapshots and audit records. No image/protected-file changes or observed image mutation attempts occurred.
- One unexpected write-capable open in RQ4-0945 generated a Volatility ntdll symbol file outside designated trial output/cache paths. The original unexpected-write count remains 1. This is not an image mutation, and prevents claiming that the whole system performs no filesystem writes.
- Network-related interruptions and an overnight pause were retained as operational history. Resumption skipped every recorded ID. The installed symbol library gained the observed symbol file; do not claim the entire runtime filesystem remained identical.

## Validation and records

All 1,302 IDs occur exactly once, with 186 in each category. Every corpus MCP request has a logged response. Product-source hashes and frozen harness hashes match across the corpus and current files. All trial image baselines have one SHA-256, and the original source image still matches it. A private manifest hashes 5,208 corpus log/summary files.

Reviewed aggregate exports: results-summary.json and validation-summary.json. Private raw evidence: artifacts/study; actual settings/checkpoints: .local. Keep those ignored directories out of Git. Public examples remain masked. Corpus prompt strings are correlated variants; no independent-sample or universal failure-probability claim is made.

## Manuscript interpretation

Section 5.4 reports direct controls, focused workflows, corpus coverage, incomplete attempts, and the symbol-file write separately. The defensible conclusion is preservation of the bound evidence image in the tested configuration and measured executions. It is not a guarantee for every model, host privilege, dependency, native operation, confidentiality property, or chain-of-custody requirement.
