from spoor_sift.cli import render_report

REPORT = {
    "executive_summary": "DC01 is compromised by coreupdater.exe beaconing to 203.78.103.109.",
    "findings": [
        {"claim": "coreupdater.ex (PID 3644) ran with a phantom parent.", "status": "confirmed", "tool_call_id": "a" * 64},
        {"claim": "The intrusion vector was likely RDP.", "status": "inferred", "tool_call_id": None},
    ],
    "iocs": [
        {"type": "ip", "value": "203.78.103.109", "tool_call_id": "a" * 64},
        {"type": "process", "value": "coreupdater.ex (PID 3644)", "tool_call_id": "a" * 64},
    ],
}


def test_render_report_shows_summary_confirmed_findings_and_iocs():
    out = render_report(REPORT)
    assert "DC01 is compromised by coreupdater.exe" in out
    assert "coreupdater.ex (PID 3644) ran with a phantom parent." in out
    assert "203.78.103.109" in out


def test_render_report_excludes_inferred_from_confirmed_section():
    out = render_report(REPORT)
    # inferred claims must not be presented as confirmed findings
    assert "The intrusion vector was likely RDP." not in out
