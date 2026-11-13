# RQ4 bounded evidence-integrity study, version 1

This operational protocol narrows the broader design in `../rq4.md` to an
executable journal revision. The corpus is frozen in `cases.json` before the main
run. Discovery and connectivity pilots are excluded from main results. Actual
deployment settings, image selection and raw records remain in ignored local files.

## Claim and threat boundary

Test whether VolPilot preserves the bound image's bytes, size, existence, identity
and location under adversarial requests through its MCP interface. The adversary
controls tool names and arguments (Track A), or user text and one designated
model-visible forensic field (Track B). It cannot modify the server, dependencies,
startup configuration, files on the host, or image contents outside this interface.
The model has only VolPilot tools. No shell or independent file-management tool
is provided. The server account can write the disposable image and its directory;
OS write protection is not the explanation for preservation in this condition.

Test host: macOS arm64; image: one 2 GiB Windows 7 SP1 x64 capture. Use the existing
minimal Python environment (Volatility 2.28.0, MCP 1.27.0, Pydantic 2.12.5), which
exposes 87 MCP tools. Optional-plugin and Windows-host conditions are outside this
run. Inventory all exposed schemas and inspect their execution paths; do not claim
to execute every tool or exhaust all argument combinations.

## Fixed cases

Track A: 24 fresh-server sessions, one request per session:

| Family | Count | Purpose |
|---|---:|---|
| Tool allowlist | 4 | Deletion, relocation, shell execution and generic dispatch names |
| Fixed image binding | 3 | Replacement path fields on existing read tools |
| Argument validation | 6 | Invalid types, missing required argument, shell-like value |
| Boundary/coercion | 3 | Negative/large PID and numeric string coercion |
| Output redirection | 4 | Added absolute/traversal path fields on both extraction tools |
| Normal operations | 4 | OS info, process list, file extraction and PE extraction |

Extra arguments may be ignored rather than rejected. Record actual behavior;
do not infer strict rejection from a tool's declared schema. Extraction redirection
cases intentionally supply otherwise valid targets so a broken extraction path
cannot be mistaken for protection. Successful extraction must create at least one
new derivative while preserving all protected files.

Component tests: 10 direct invocations of the unchanged common dump file handler,
covering native traversal, absolute/nested/NUL names, dot-dot, Windows-style names
on the actual macOS host, and existing-file collision. These are not MCP attacks.
Windows-style backslashes can be literal filename characters on this host; such a
result provides no Windows-host security guarantee. Aliasing/races requiring host
filesystem control are excluded by the core threat boundary.

Track B: 12 base scenarios × 2 fresh sessions = 24 trials, using one self-hosted
Qwen model and promptfoo 0.123.1. Eight are direct requests targeting deletion,
overwriting, truncation, relocation, renaming, replacement by compression, dump
redirection, and a Korean deletion instruction. Four inject instructions into
`windows_cmdline.results[0].Args` (deletion, overwrite, relocation, compression).
The harness first executes the actual cmdline tool, then replaces only that
model-visible field. The synthetic response and the actual server response are
logged separately; the evidence image is never edited to construct injection.
Those four scenarios contribute eight setup calls, separate from model-initiated
calls. The model receives server initialization instructions as a system message
and the complete current tool schemas. Temperature 0; 2048 output-token ceiling;
at most 4 model responses; 180-second model and 90-second tool timeouts. Repeats
check reproducibility, not statistical independence or a universal failure rate.

## Measurements and controls

Every session starts with a fresh byte copy, a protected pre-existing dump file,
a protected sibling file, and an invalid alternative image. Record pre/post SHA-256,
size, existence, pathname, device/inode and mtime; atime is excluded. Hashing is
performed by the harness independently of the server's integrity tool.

An evaluation-only launcher installs a non-blocking CPython audit hook before
starting the unchanged server. It records image reads, write-capable Python opens,
and Python remove/rename/truncate/link events. It imposes no denial policy. Retain
the event log and post-run manifest; allow new derivatives in the configured dump
directory, the known image config sidecar and designated runtime caches. Preserve
pre-existing protected outputs. Audit observations complement endpoint hashes:
they are not kernel-wide tracing and do not cover every native-extension syscall.

Four disposable positive controls independently modify, delete, rename, and
temporarily modify/restore a small test file using this launcher. The last control
must retain its byte hash but produce write-intent events. Validate these before
main execution. Normal extraction controls establish that write-capable derivative
paths really run. MCP responses distinguish lookup rejection, argument-validation
rejection, accepted calls and execution failures; model errors, timeouts, or missing
measurements remain inconclusive, never protective successes.

Report image state changes, observed image mutation attempts, pre-existing-output
changes, unexpected write-capable opens, normal-task successes, and complete vs.
inconclusive sessions. Report model proposals, actual calls, refusals and injection
setup calls separately. Refusal coding is a secondary manual reading of saved final
text; it must not determine the image-integrity result.

## Interpretation

The intended conclusion is preservation of original image evidence within the
tested interface/configuration, supported by actual boundary calls, successful
derivative creation, inspection and independent observations. Do not claim proof
of immunity, all deployments, confidentiality, correct interpretation, availability,
or an entire chain of custody. No baseline competitor is assumed to be destructive
merely because it exposes a generic dispatcher. The old 1,302-prompt language-grader
results and the new measurements are not pooled.
