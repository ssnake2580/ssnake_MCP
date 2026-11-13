"""The IOC→finding bridge: maps a report's structured IOCs to gradeable findings.

Lives next to score() because findings are its input. The bridge must tolerate
the rich, metadata-laden IOC values a real agent emits (a malware process is
reported as 'coreupdater.ex (PID 3644, …)', not a bare filename) and must not
double-count one file reported two ways.
"""

from spoor_sift.accuracy import findings_from_report

CITE = "a" * 64


def _ioc(ioc_type, value, cite=CITE):
    return {"type": ioc_type, "value": value, "tool_call_id": cite}


def test_process_ioc_with_metadata_yields_clean_file_token():
    """Trailing 'process (PID …)' metadata must not defeat scoring — the bridge
    extracts the leading filename token and grades that."""
    report = {"iocs": [_ioc("process", "coreupdater.ex (PID 3644, Session 2, PPID 2244 phantom)")]}
    findings, unscored = findings_from_report(report, {CITE})
    assert findings == [
        {"category": "file", "value": "coreupdater.ex", "status": "confirmed", "tool_call_id": CITE}
    ]
    assert unscored == []


def test_same_file_as_process_and_path_is_not_double_counted():
    """spoolsv.exe reported as both a process and a path is one file, not two FPs."""
    report = {
        "iocs": [
            _ioc("process", "spoolsv.exe (PID 3724) - 4 injected VadS regions"),
            _ioc("path", "C:\\Windows\\System32\\spoolsv.exe"),
        ]
    }
    files = [f for f in findings_from_report(report, {CITE})[0] if f["category"] == "file"]
    assert len(files) == 1
    assert files[0]["value"] == "spoolsv.exe"


def test_ip_port_is_stripped_and_uncited_is_inferred():
    report = {
        "iocs": [
            _ioc("ip", "203.78.103.109:443", cite="b" * 64),
            _ioc("ip", "10.0.0.1", cite=None),
        ]
    }
    findings, _ = findings_from_report(report, {"b" * 64})
    assert findings[0] == {
        "category": "ip",
        "value": "203.78.103.109",
        "status": "confirmed",
        "tool_call_id": "b" * 64,
    }
    assert findings[1]["status"] == "inferred"  # citation not in the verified chain


def test_non_file_non_ip_iocs_are_unscored_not_dropped():
    report = {"iocs": [_ioc("other", "Phantom PPID 2244"), _ioc("url", "203.78.103.109:443/tcp")]}
    findings, unscored = findings_from_report(report, set())
    assert findings == []
    assert len(unscored) == 2
