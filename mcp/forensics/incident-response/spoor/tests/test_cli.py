import json
from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.cli import main


def _make_audit(path: Path) -> AuditLog:
    log = AuditLog(path, clock=lambda: "2026-06-09T12:00:00+00:00")
    log.append(tool="vol_pslist", args={}, exit_code=0, stdout="a")
    log.append(tool="vol_netscan", args={}, exit_code=0, stdout="b")
    return log


def test_verify_audit_reports_intact(tmp_path: Path, capsys):
    path = tmp_path / "audit.jsonl"
    _make_audit(path)
    rc = main(["verify-audit", str(path)])
    out = capsys.readouterr().out.lower()
    assert rc == 0
    assert "intact" in out


def test_verify_audit_detects_tamper(tmp_path: Path, capsys):
    path = tmp_path / "audit.jsonl"
    _make_audit(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["exit_code"] = 99
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = main(["verify-audit", str(path)])
    out = capsys.readouterr().out.lower()
    assert rc != 0
    assert "broken" in out and "seq 0" in out


def test_demo_guardrails_all_blocked(capsys):
    rc = main(["demo-guardrails"])
    out = capsys.readouterr().out.lower()
    assert rc == 0
    assert out.count("blocked") >= 4
    assert "traversal" in out and "symlink" in out and "allow-list" in out


def test_accuracy_report_prints_metrics(tmp_path: Path, capsys):
    findings = [{"category": "ip", "value": "194.61.24.102", "status": "confirmed", "tool_call_id": "a" * 64}]
    gt = {"iocs": {"ips": [{"value": "194.61.24.102"}], "files": []}}
    fpath = tmp_path / "findings.json"
    fpath.write_text(json.dumps(findings), encoding="utf-8")
    gpath = tmp_path / "gt.json"
    gpath.write_text(json.dumps(gt), encoding="utf-8")

    rc = main(["accuracy-report", str(fpath), str(gpath)])
    out = capsys.readouterr().out.lower()
    assert rc == 0
    assert "precision" in out and "recall" in out and "f1" in out and "hallucination" in out
