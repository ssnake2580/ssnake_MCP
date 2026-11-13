#!/usr/bin/env bash
# Spoor — silent demo walkthrough. No voice: the on-screen banners narrate.
# $0 and self-contained — runs only free commands off the committed real run.
# Beat ② (the live `make real` kickoff) is recorded SEPARATELY and spliced in
# editing; never bake a paid, evidence-dependent run into this script.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_DIR="${1:-runs/2026-06-12-231634-case001-real}"          # canonical run: verdict/audit/accuracy
SC_RUN="${2:-runs/2026-06-14-155749-case001-real}"           # run exhibiting the induced self-correction
GT="datasets/case001_ground_truth_dc01_memory.json"
UV="${UV:-uv}"
BAR="════════════════════════════════════════════════════════════════════"

banner() { clear; printf '\n%s\n  %s\n%s\n\n' "$BAR" "$1" "$BAR"; }
pause()  { printf '  [ press enter ▸ ] '; read -r _ || true; printf '\n'; }
runcmd() { printf '  $ %s\n\n' "$*"; "$@"; }

banner "SPOOR — find evil, and prove it.    ·    FIND EVIL! / SANS hackathon"
pause

banner "① EVIDENCE — DC01 domain controller, suspected compromise. 2.1 GB RAM capture, READ-ONLY."
if [ -f evidence/case001/citadeldc01.mem ]; then
  runcmd ls -lh evidence/case001/citadeldc01.mem
else
  printf '  (evidence image is gitignored/local — integrity hashes from the committed run:)\n\n'
  "$UV" run python - "$RUN_DIR" <<'PY'
import json, sys
m = json.load(open(f"{sys.argv[1]}/run_meta.json"))
print("    pre :", m["evidence_sha256_pre"])
print("    post:", m["evidence_sha256_post"])
print("    integrity_ok:", m["evidence_integrity_ok"])
PY
fi
pause

banner "② AUTONOMOUS RUN — one prompt; a multi-agent graph works the case.  [ splice live 'make real' clip here ]"
printf "  Recorded separately: 'make real' prints 'hashing evidence… <sha256>',\n  'lead/specialist: sonnet', then streams '▶ supervisor → triage → timeline → ioc → reporter'.\n"
pause

banner "②b SELF-CORRECTION — forensic tools fail mid-case; Spoor reasons and recovers (no crash, no fabrication)."
runcmd "$UV" run spoor show-selfcorrect "$SC_RUN"
pause

banner "③ THE VERDICT — real evil found, every claim tied to evidence."
runcmd "$UV" run spoor show-report "$RUN_DIR"
pause

banner "④ CAN YOU TRUST IT? Every confirmed finding cites a tool_call_id in a hash-chained audit log."
runcmd "$UV" run spoor verify-audit "$RUN_DIR/audit.jsonl"
pause

banner "⑤ TRY TO MAKE IT MISBEHAVE — read-only jail, allow-listed exec, evidence off-limits."
runcmd "$UV" run spoor demo-guardrails
pause

banner "⑥ THE NUMBERS — honest, on real evidence. Hallucination 0.000."
runcmd "$UV" run spoor accuracy-report "$RUN_DIR/findings.json" "$GT"
pause

banner "SPOOR — github.com/RECTOR-LABS/spoor"
