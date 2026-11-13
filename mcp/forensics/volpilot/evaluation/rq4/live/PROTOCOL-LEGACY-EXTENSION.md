# Pre-run scope extension: legacy replay

The user requested more than 1,000 model trials after the 24-case focused protocol
had started. Preserve those trials and their original freeze record. Add a separate
regression stratum of all 1,302 legacy prompts (186 per researcher-defined category),
each once through the **new** measured model/MCP harness. The corpus has 1,302 unique
IDs and exact prompt strings; paraphrases are still correlated, not independent
risk types. This addition makes 1,326 planned model trials, separate from 24 direct
MCP sessions, 10 file-handler component tests, and four measurement controls.

Keep each legacy prompt intact after a fixed preamble binding historical filenames
to the current disposable image. This avoids testing requests against nonexistent
historical filenames. The preamble, corpus hash and runtime settings are retained
in the private manifest. Reuse the frozen study provider and observer: same model,
complete tool inventory, system instructions, temperature, token and turn budgets,
per-trial copies, fresh servers, measurements and decision rules.

Run at most two independent sessions concurrently, in batches of 50, with an
outcome saved immediately for each case. Each corpus ID receives one attempt;
restarting the runner skips all recorded IDs, including inconclusive attempts.
Do not silently retry a failure until it passes. Stop a batch sequence for an
observed state change, unexpected write, or three incomplete trials in a batch,
and investigate before resuming. Retain original failed records and disclose any
subsequent diagnostic reruns separately. Aggregation must show denominators for
completed, inconclusive, model-dispatched and server-rejected requests.

This replay replaces the old text-judge results for the current evaluation; it
does not reinterpret the old results as filesystem evidence. The additional volume
supports breadth across the existing corpus, not a claim of exhaustive security.
Keep real endpoints/configuration and raw transcripts in ignored local directories;
publish only masked templates and reviewed aggregate exports.

## Operational diagnosis after the first 50 attempts

The batch pause rule triggered after 47 workflows completed and three reached the
fixed four-response limit while invoking normal analysis tools. All 50 had complete
filesystem snapshots/audit records; none changed protected files or attempted to
write the image. The exact exception was diagnosed and logged privately. The runner
may now be resumed with `--acknowledge-round-limits`, which suppresses repeated
pauses only for that diagnosed exception. It does not increase the response budget,
change the model/measurement protocol, discard records, retry those cases, or
relabel them as completed workflows. Other unknown failures and integrity anomalies
still trigger investigation. Report workflow completion and filesystem-observation
completeness separately.
