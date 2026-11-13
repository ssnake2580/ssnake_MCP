# Follow-up of 199 incomplete attempts

Authorized on 2026-09-23 after the user rejected treating attempt-record completion as completed experimental review. Manuscript revisions are on hold until this review and follow-up have been assessed.

The original 1,302 records are immutable. `incomplete-review.json` identifies all 199 incomplete IDs and their observed execution coverage. This follow-up runs each of those IDs once in a distinct `B-followup` stratum, linking to its original run ID. It is not a replacement dataset, and selective repeats until success are prohibited.

Use the same original case prompt (including its image-binding preamble), model, tool schemas, temperature, image and product implementation. Fresh writable image copies and server sessions remain required. Model-response budget increases from 4 to 8 and output-token budget from 2048 to 4096; model/tool timeouts remain 180/90 seconds. Execute sequentially to reduce concurrent load. These changed budgets mean follow-up outcomes are reported separately, not pooled as original-protocol successes. `study_followup.py` is a separately hashed copy of the frozen original with only the artifact directory and stated budgets changed.

A model-list connectivity probe precedes each attempt, with a short inference health check at runner startup. Any transport failure, missing record, protected-state change, or unexpected write stops the sequence for diagnosis. Budget-exhausted attempts remain incomplete and are not retried automatically. A recorded follow-up ID is skipped on restart, regardless of outcome. Do not introduce artificial termination prompts or remove tool options to force completion.

Preserve all transcripts, observer records, before/after measurements and both attempt identities. Keep actual settings and raw records in ignored directories. Pristine disposable fixtures may be removed after their state is recorded; anomalous fixtures remain retained. Completion of this follow-up sequence does not itself establish that every workflow completed; review outstanding cases before any paper revision.
