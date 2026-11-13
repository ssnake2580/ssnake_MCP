import math

from spoor_sift.accuracy import score

GT = {
    "iocs": {
        "ips": [{"value": "194.61.24.102", "role": "attacker"}],
        "files": [{"path": "C:\\Windows\\System32\\coreupdate.exe", "role": "malware"}],
    }
}


def _confirmed(category, value, cite="a" * 64):
    return {"category": category, "value": value, "status": "confirmed", "tool_call_id": cite}


def test_perfect_findings_score_1():
    findings = [
        _confirmed("ip", "194.61.24.102"),
        _confirmed("file", "C:\\Windows\\System32\\coreupdate.exe"),
    ]
    r = score(findings, GT)
    assert r.precision == 1.0 and r.recall == 1.0 and r.f1 == 1.0
    assert r.hallucination_rate == 0.0
    assert r.false_positives == [] and r.false_negatives == []


def test_false_positive_lowers_precision():
    findings = [
        _confirmed("ip", "194.61.24.102"),
        _confirmed("file", "C:\\Windows\\System32\\coreupdate.exe"),
        _confirmed("ip", "8.8.8.8"),  # not in ground truth
    ]
    r = score(findings, GT)
    assert r.recall == 1.0
    assert math.isclose(r.precision, 2 / 3, rel_tol=1e-9)
    assert any(f["value"] == "8.8.8.8" for f in r.false_positives)


def test_missing_finding_lowers_recall():
    findings = [_confirmed("ip", "194.61.24.102")]  # file IOC missed
    r = score(findings, GT)
    assert r.precision == 1.0
    assert math.isclose(r.recall, 0.5, rel_tol=1e-9)
    assert any("coreupdate.exe" in gt["value"].lower() for gt in r.false_negatives)


def test_uncited_confirmed_finding_is_a_hallucination():
    findings = [
        _confirmed("ip", "194.61.24.102"),
        _confirmed("file", "C:\\Windows\\System32\\coreupdate.exe", cite=None),
    ]
    r = score(findings, GT)
    assert math.isclose(r.hallucination_rate, 0.5, rel_tol=1e-9)


def test_inferred_findings_are_not_false_positives():
    findings = [
        _confirmed("ip", "194.61.24.102"),
        _confirmed("file", "C:\\Windows\\System32\\coreupdate.exe"),
        {"category": "ip", "value": "1.2.3.4", "status": "inferred", "tool_call_id": None},
    ]
    r = score(findings, GT)
    assert r.precision == 1.0
    assert r.false_positives == []


def test_truncated_windows_process_name_matches_full_basename():
    """Windows pslist truncates the EPROCESS ImageFileName to ~14 chars, so a
    real malware process surfaces as 'coreupdater.ex' while the answer key holds
    the full 'coreupdater.exe'. The scorer must still credit the detection."""
    gt = {"iocs": {"files": [{"path": "C:\\Windows\\System32\\coreupdater.exe", "role": "malware"}]}}
    findings = [_confirmed("file", "coreupdater.ex")]  # 14-char ImageFileName truncation
    r = score(findings, gt)
    assert r.recall == 1.0
    assert r.false_negatives == []
    assert any(f["value"] == "coreupdater.ex" for f in r.true_positives)
