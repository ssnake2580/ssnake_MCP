import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "web" / "data" / "case001.json"


def test_export_produces_valid_site_data():
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "export_site_data.py")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(OUT.read_text())

    # 8 byte-exact audit records, each carrying every content + hash field
    assert len(data["audit"]) == 8
    fields = {"seq", "ts", "tool", "args", "exit_code", "stdout_sha256", "prev_hash", "hash"}
    for rec in data["audit"]:
        assert fields <= set(rec)
    # known anchors
    assert data["audit"][0]["prev_hash"] == "0" * 64
    assert data["audit"][2]["hash"] == "cb5ea571ee90915f4e7b36a9b241ce2bfde7f883c44641c5381e0b986f6c81ac"
    assert data["audit"][7]["hash"] == "50be50f15a60698cb99c1d0970bcc5e37ea308f1a5aae8906c4cf93c0c0d6283"

    # integrity + verdict + accuracy (computed, not parsed)
    assert data["meta"]["evidence_integrity_ok"] is True
    assert data["verdict"]["enforcement"]["confirmed"] == 19
    assert data["accuracy"]["precision"] == 0.25
    assert data["accuracy"]["recall"] == 0.5
    assert data["accuracy"]["hallucination_rate"] == 0.0
    assert data["accuracy"]["f1"] == 0.333
    assert data["accuracy"]["pre_correction"]["precision"] == 0.333
    assert data["accuracy"]["pre_correction"]["recall"] == 0.25
    assert data["accuracy"]["pre_correction"]["f1"] == 0.286
