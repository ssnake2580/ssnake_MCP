# VolPilot research artifact

This repository contains the implementation and selected evaluation materials for anonymous review. Product source and measured data are preserved from the research workspace; this release reorganizes public documentation and omits private and historical working records.

## Start here

- [Installation and usage](README.md)
- [Tool catalog](TOOL_CATALOG.md)
- [RQ1: execution time and output size](evaluation/rq1/rq1.md)
- [RQ2: plugin selection](evaluation/rq2/rq2.md)
- [RQ3: participant study](evaluation/rq3/rq3.md)
- [RQ4: adversarial tool use](evaluation/rq4/rq4.md)
- [RQ4 public data and field guide](evaluation/rq4/live/public-csv/README.md)

## Included and excluded materials

Included: product code, dependency lockfiles, anonymized participant measurements, benchmark questions with source attribution, baseline patches and measurements, current RQ4 protocols, evaluation harnesses, reviewed aggregates, and masked public CSV exports.

Excluded: memory images, malware binaries, participant identities and private answers, raw model/MCP transcripts, actual connection settings and credentials, local execution checkpoints, internal review notes, installed dependencies, caches, and superseded RQ4 language-grader outputs/configuration. Third-party references and licenses are retained.

Public tables can be inspected without a model endpoint or private logs. Re-running experiments requires suitable locally supplied images, a configured model where applicable, and the prerequisites described in each evaluation directory. Scripts that verify or regenerate private measurements require the retained private records; this repository does not claim to bundle those records. Existing measurements should not be overwritten when reproducing experiments.

Product modules and evaluation scripts are retained without behavioral changes. Some historical harness comments reference private paths or bundled-runtime fallbacks; configure the documented public templates and provide Node.js/uv on PATH. No experiment was re-run when packaging this release.

## Interpretation

RQ1 distinguishes measured times, corrected baseline output and extrapolated token costs. RQ2 reports reference-plugin selection. RQ3 reports completion time and perceived convenience. RQ4 separates workflow termination, actual tool execution and observed image integrity; original and follow-up attempts retain their own outcomes. Consult each write-up before interpreting a count as a success rate.
