# RQ4 measured evaluation

This directory contains the connectivity pilot and the subsequent measured RQ4 study.
The frozen protocol is in `PROTOCOL.md`; the large-corpus extension is in
`PROTOCOL-LEGACY-EXTENSION.md`. The three-case pilot remains separate from study results. It uses promptfoo 0.123.1 and a custom provider to execute a
real OpenAI-compatible model → MCP → VolPilot tool loop. Product code is unchanged.

## Public templates and private execution settings

Public files: `config.example.json`, `promptfooconfig.pilot.yaml`, `provider.cjs`,
`harness.py`, `run-pilot.sh`, package metadata and this guide.

Private, Git-ignored directories:

- `.local/`: actual server address, model ID, absolute image path and promptfoo state.
- `artifacts/`: model prompts/responses, actual MCP requests/responses, hashes,
  local paths and per-trial summaries. These are raw private research records.
- `.cache/`, `node_modules/`: local runtime data and installed dependencies.

Copy `config.example.json` to `.local/config.json` and replace placeholders locally.
Use the environment variable named by `api_key_env` for an API key if required;
never put key values in the template or config. Actual connection settings must
not be copied into public documentation. Do not force-add ignored files. Create
a separately reviewed, anonymized export when preparing public research artifacts.

## Setup and execution

1. Install Node.js >=22.22.0, pnpm, and uv; place them on PATH.
2. From the VolPilot directory, prepare the pinned Python environment with
   `uv sync --frozen`. Use `--extra full` only if the chosen protocol requires
   optional plugins. Different extras change the exposed tool inventory.
3. From this directory, run `pnpm install --frozen-lockfile`.
4. Populate `.local/config.json` as described above. The model must support the
   OpenAI-compatible `/v1/chat/completions` API and function calling.
5. Run `bash run-pilot.sh`. This script can also discover this machine's bundled
   Node runtime; other machines should supply Node on PATH.

`RQ4_UV` can override the uv executable for the provider. Python execution always
uses `uv run --no-sync --offline python`, so it does not alter dependencies at run
time. Request and tool timeouts and model round limits are set in the private config.

The pilot runs sequentially, without promptfoo caching or an external LLM judge.
It supplies the server's MCP initialization instructions as the model system
message and advertises **all tools exposed by the installed environment**.
Only this VolPilot server is connected; no general shell/file tool is supplied.
Each trial starts a new MCP server with a full, writable image copy and a separate
output directory. The original image is read only to make that copy.
Completed trials with unchanged protected state remove their temporary fixture;
failed/incomplete trials retain it for diagnosis. Each retained copy uses roughly
the size of the source image, plus any extraction output.

## Records and interpretation

`artifacts/<trial>/events.jsonl` contains model requests/responses, schemas, host
dispatch decisions, MCP requests/responses, dependency versions, server-file
hashes, and pre/post protected-state snapshots. `summary.json` contains counters,
completion status and final model text. `server.stderr.log` contains server logs.
The promptfoo summary points to these artifacts.

The normal control must actually invoke `verify_image_integrity` successfully.
The two adversarial cases check endpoint preservation, not refusal quality.
Model refusal without a tool call provides no evidence of server-side rejection.
The delivered-call counter requires a returned MCP response; an outstanding
request on timeout remains visible in the event log and is inconclusive.

These pilot assertions cover the image and one pre-existing output sentinel
(hash, size, path, existence, file identity and mtime). Other fixture files are
recorded in a post-run manifest. This is not global file-operation tracing;
outside-directory writes and temporary mutation followed by restoration are
not comprehensively observed. Reading-related atime is not scored as corruption.
New derivatives and cache files are not automatically classified as corruption.

The completed study extends this pilot with direct MCP requests, measurement
controls, extraction controls, component tests and indirect-injection fixtures.
See the protocols and completed results below; the three-case pilot is a separate
preliminary check, not the full RQ4 study.

Provider interface reference: https://www.promptfoo.dev/docs/providers/custom-api/

## Main study and large-corpus replay

- `study.py --direct`: 24 deterministic MCP sessions, including four normal controls.
- `controls.py`: four measurement controls and ten isolated file-handler tests.
- `bash run-study.sh`: 12 focused Qwen scenarios, twice each (24 model trials).
- From VolPilot: `uv run --no-sync --offline python evaluation/rq4/live/run_legacy.py`:
  checkpointed 1,302-case replay, two concurrent sessions, batches of 50.
- `analyze.py`: aggregate export in `results-summary.json`; status stays
  `in_progress` until all expected corpus IDs have outcomes. Inconclusive counts
  remain separate even once every ID has been attempted.

For all Python commands, set `UV_CACHE_DIR` to a writable location when the default
cache is unavailable. Configure the extraction fixture through the private
`.local/fixture-parameters.json` (PID, integer module base and filename regex),
selected using discovery. The initial PE target produced empty output; the documented PE supplement validates nonempty extraction without replacing initial records.
Start from `fixture-parameters.example.json`; replace the PID and base placeholders
with JSON integers, not quoted strings. This template contains no actual image
identifiers or process addresses. In the frozen main runner, the effective budgets
are fixed in `study.py`: temperature 0, 2048 output tokens, four responses,
180-second model timeout and 90-second tool timeout. The similarly named fields
in `config.example.json` configure the earlier pilot; the main runner reads only
connection/model/image/authentication settings from that file. Raw records retain
the config snapshot and the harness hash, and `PROTOCOL.md` states effective limits.
Do not publish that local setup file. The runner keeps the original image untouched.

The legacy runner skips recorded IDs, including inconclusive attempts, on restart.
It stops for missing outcomes, protected-state anomalies, or at least three
incomplete trials per batch. Inspect the saved batch log before restarting; do not
silently replace an unsuccessful trial. Raw promptfoo outputs, observer logs and
snapshots remain private. The aggregate JSON contains counts, not endpoints,
usernames, source-image paths or raw model/forensic text.


## Completed results

See [RESULTS.md](RESULTS.md) for the final counts and limitations, including 199 incomplete corpus workflows and one symbol-library write. The original 24 direct requests are supplemented by three PE-validation requests; initial empty PE outputs remain recorded. `results-summary.json` and `validation-summary.json` are aggregate-only exports. No further corpus resumption is required.


## Final incomplete-case adjudication (2026-09-24)

The separate 199-case follow-up and log review are complete: 106 workflows completed, 78 reached the response limit, and 15 ended in a model read timeout. No image change was observed. See [FOLLOWUP-RESULTS.md](FOLLOWUP-RESULTS.md), [per-case verdicts](followup-review.json), and `verify_followup.py`. Original results are preserved; no further retries are planned. Manuscript/PDF revision remains subject to an explicit user instruction.
