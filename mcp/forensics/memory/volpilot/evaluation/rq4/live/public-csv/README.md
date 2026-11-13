# Public RQ4 CSV artifact

These UTF-8-with-BOM, quoted CSVs are measured-result exports, not promptfoo language-grader pass/fail scores. Open with a CSV-aware reader; prompt fields can contain embedded newlines. Booleans use True/False; blank follow-up call counts mean not scheduled, not zero. Full model outputs, evidence contents, local filesystem paths, endpoints and credentials are excluded. Legacy historical grader results are not pooled.

| File | Rows | Unit / interpretation |
|---|---:|---|
| case-catalog.csv | 1302 | One unique corpus ID and original prompt, with original/follow-up outcome columns |
| trial-results.csv | 1501 | 1302 original + 199 separate follow-up attempts; key is stratum + case_id |
| category-results.csv | 14 | Seven categories, with separate original and follow-up totals |
| followup-transitions.csv | 4 | Original incomplete reason to follow-up outcome |
| representative-prompts.csv | 7 | Actual corpus examples with stable case IDs |
| experiment-inventory.csv | 7 | Experimental strata; component/control counts are not model attempts |
| review-questions.csv | 15 | Questions and evidence-based interpretation for artifact readers |

## Field interpretation

- `case_id` identifies the unchanged prompt; `run_id` identifies an attempt. `original_run_id` links follow-ups to originals. Follow-ups do not add unique prompts.
- `prompt` is the original corpus text. `presented_prompt_template` includes the common image-binding preamble; `{IMAGE}` is substituted at runtime with each private disposable fixture path. Literal adversarial filenames such as win11.mem are corpus content, not actual local evidence paths.
- `workflow_complete` and `outcome` describe model termination. They are not an integrity pass rate. `review_status=complete` means log adjudication is done even if the workflow remains incomplete.
- `model_requests`, `model_responses` and `actual_tool_calls` distinguish no response, verbal-only response and MCP execution. `tool_calls_by_name` is JSON within a CSV cell. `all_mcp_requests_responded` is verified from event pairs.
- `max_model_responses`, `max_output_tokens`, temperature and timeout columns give effective settings verified from requests/code, not the stale protocol settings summary. Each output-token limit applies per response.
- `image_unchanged` covers compared metadata and bytes; SHA-256 columns expose content hashes only. `protected_outputs_preserved` covers pre-existing protected files. `audit_available` and `image_mutation_attempts` concern Python audit coverage, not all native-library writes.
- `unexpected_write_opens` counts write-capable open events, not unique files or evidence-image changes. `write_diagnosis` retains the symbol-generation explanation.
- `followup_scheduled=False` on follow-up rows means no further retry is scheduled. Catalog `followup_performed` is the direct way to determine whether an original case received a follow-up. `original_failure` is blank on original rows.
- `stopping_stage` is detailed for follow-ups; original rows retain the original outcome category. Trial coverage and image preservation must be interpreted separately.

## Regeneration and checks

From VolPilot, run `uv run --no-sync --offline python evaluation/rq4/live/export_artifact_csv.py` with the private original/follow-up artifacts and validated followup-review.json present. This regenerates the four measured case/category/transition tables and asserts 1302 original IDs, 199 one-to-one follow-ups, 1501 unique attempt keys, and 1103/106 workflow completions. The other three CSVs are curated descriptions and exact selected corpus examples; they are checked against the catalog. See ../verify_followup.py for raw-log and source-hash verification.

The seven CSVs support inspection of reported data without private logs. Independent verification of every measurement requires the retained raw records; these exports do not imply that raw forensic data have been publicly released. Ten component tests and four positive measurement controls are separate from the 1552 recorded MCP/model sessions (27 direct + 24 focused + 1302 original + 199 follow-up); this session total is not a count of unique attacks.
