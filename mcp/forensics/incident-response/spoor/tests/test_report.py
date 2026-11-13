"""The reporter's confirmed-vs-inferred contract, enforced in code (not prompt).

A finding may claim status "confirmed" ONLY if it cites a tool_call_id that exists
in the verified hash-chained audit log. Anything else — missing citation, fabricated
citation, or a broken chain — is downgraded to an inference, deterministically.
"""

import json
from pathlib import Path

from langchain_core.messages import ToolMessage
from langgraph.types import Command

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.report import build_submit_report_tool, enforce_citation_contract


def _audit_with_two_calls(tmp_path: Path) -> tuple[AuditLog, str, str]:
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    r0 = audit.append(
        tool="vol_pslist", args={"image": "mem.raw"}, exit_code=0, stdout='{"rows": 2}'
    )
    r1 = audit.append(
        tool="vol_netscan", args={"image": "mem.raw"}, exit_code=0, stdout='{"conns": 1}'
    )
    return audit, r0.tool_call_id, r1.tool_call_id


def _report(findings: list[dict]) -> dict:
    return {
        "executive_summary": "Host shows signs of compromise.",
        "findings": findings,
        "iocs": [{"type": "ip", "value": "203.0.113.5", "tool_call_id": None}],
        "open_questions": ["Initial access vector unconfirmed"],
    }


def test_confirmed_finding_with_real_citation_stays_confirmed(tmp_path: Path):
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    report = _report(
        [{"claim": "svch0st.exe (PID 666) is running", "status": "confirmed", "tool_call_id": call_a}]
    )

    enforced = enforce_citation_contract(report, audit)

    assert enforced["findings"][0]["status"] == "confirmed"
    assert enforced["findings"][0]["tool_call_id"] == call_a
    assert enforced["enforcement"] == {
        "audit_chain_ok": True,
        "confirmed": 1,
        "inferred": 0,
        "downgraded": 0,
    }


def test_confirmed_finding_with_fabricated_citation_is_downgraded(tmp_path: Path):
    # A hallucinated citation — a tool_call_id that never happened — must not survive.
    audit, _, _ = _audit_with_two_calls(tmp_path)
    fake_id = "f" * 64
    report = _report(
        [{"claim": "Beacon to 198.51.100.9 every 60s", "status": "confirmed", "tool_call_id": fake_id}]
    )

    enforced = enforce_citation_contract(report, audit)

    finding = enforced["findings"][0]
    assert finding["status"] == "inferred"
    assert "not found in the audit log" in finding["downgraded_reason"]
    assert enforced["enforcement"]["confirmed"] == 0
    assert enforced["enforcement"]["inferred"] == 1
    assert enforced["enforcement"]["downgraded"] == 1


def test_confirmed_finding_without_citation_is_downgraded(tmp_path: Path):
    audit, _, _ = _audit_with_two_calls(tmp_path)
    report = _report([{"claim": "Lateral movement to DC01", "status": "confirmed"}])

    enforced = enforce_citation_contract(report, audit)

    finding = enforced["findings"][0]
    assert finding["status"] == "inferred"
    assert "no tool_call_id" in finding["downgraded_reason"]
    assert enforced["enforcement"]["downgraded"] == 1


def test_inferred_findings_pass_through_untouched(tmp_path: Path):
    # An honest inference needs no citation and must not be penalized.
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    report = _report(
        [
            {"claim": "PID 666 is suspicious", "status": "confirmed", "tool_call_id": call_a},
            {"claim": "Likely phishing initial access", "status": "inferred"},
        ]
    )

    enforced = enforce_citation_contract(report, audit)

    inference = enforced["findings"][1]
    assert inference["status"] == "inferred"
    assert "downgraded_reason" not in inference
    assert enforced["enforcement"] == {
        "audit_chain_ok": True,
        "confirmed": 1,
        "inferred": 1,
        "downgraded": 0,
    }


def test_broken_audit_chain_voids_all_confirmed_findings(tmp_path: Path):
    # If the trail itself can't be trusted, no citation into it can confirm anything.
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["exit_code"] = 99
    lines[0] = json.dumps(tampered)
    audit.path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")

    report = _report(
        [{"claim": "svch0st.exe (PID 666) is running", "status": "confirmed", "tool_call_id": call_a}]
    )
    enforced = enforce_citation_contract(report, audit)

    finding = enforced["findings"][0]
    assert finding["status"] == "inferred"
    assert "audit chain" in finding["downgraded_reason"]
    assert enforced["enforcement"]["audit_chain_ok"] is False
    assert enforced["enforcement"]["confirmed"] == 0
    assert enforced["enforcement"]["downgraded"] == 1


def test_submit_report_tool_enforces_and_updates_state(tmp_path: Path):
    # The reporter agent's only exit: a tool that (1) applies the contract in code,
    # (2) writes the ENFORCED report into graph state, (3) seals the submission
    # into the audit chain so the report itself is tamper-evident.
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    tool = build_submit_report_tool(audit)
    assert tool.name == "submit_report"

    command = tool.invoke(
        {
            "type": "tool_call",
            "id": "call_reporter_1",
            "name": "submit_report",
            "args": {
                "executive_summary": "Host compromised via svch0st.exe.",
                "findings": [
                    {"claim": "svch0st.exe (PID 666) running", "status": "confirmed", "tool_call_id": call_a},
                    {"claim": "Beaconing C2", "status": "confirmed", "tool_call_id": "f" * 64},
                ],
                "iocs": [{"type": "process", "value": "svch0st.exe", "tool_call_id": call_a}],
                "open_questions": ["Initial access vector"],
            },
        }
    )

    assert isinstance(command, Command)
    report = command.update["report"]
    assert report["enforcement"]["confirmed"] == 1
    assert report["enforcement"]["downgraded"] == 1
    assert report["findings"][1]["status"] == "inferred"
    # enforced data lands in the case state, for downstream consumers
    assert command.update["findings"] == report["findings"]
    assert command.update["iocs"] == report["iocs"]
    assert command.update["open_questions"] == ["Initial access vector"]
    # the graph requires a ToolMessage answering the call; it carries the enforced report
    tool_message = command.update["messages"][0]
    assert isinstance(tool_message, ToolMessage)
    assert tool_message.tool_call_id == "call_reporter_1"
    assert json.loads(tool_message.content)["enforcement"]["downgraded"] == 1
    # the submission is sealed into the chain: one new record, chain intact
    sealed = audit.records()[-1]
    assert sealed.tool == "submit_report"
    assert report["report_audit_id"] == sealed.tool_call_id
    assert audit.verify().ok


def test_submit_report_persists_enforced_report_to_disk(tmp_path: Path):
    # Durability: the report is the case's whole deliverable. It must hit disk the
    # instant it is produced, so a later graph/API failure (e.g. the supervisor's
    # epilogue 403'ing) can never discard a report that was already generated.
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    report_path = tmp_path / "out" / "report.json"
    tool = build_submit_report_tool(audit, report_path=report_path)

    tool.invoke(
        {
            "type": "tool_call",
            "id": "call_reporter_1",
            "name": "submit_report",
            "args": {
                "executive_summary": "Host compromised.",
                "findings": [{"claim": "svch0st.exe running", "status": "confirmed", "tool_call_id": call_a}],
                "iocs": [{"type": "process", "value": "svch0st.exe", "tool_call_id": call_a}],
                "open_questions": [],
            },
        }
    )

    assert report_path.exists()  # written even though the graph never "finished"
    on_disk = json.loads(report_path.read_text())
    assert on_disk["enforcement"]["confirmed"] == 1
    assert on_disk["report_audit_id"] == audit.records()[-1].tool_call_id


def test_submit_report_without_path_still_works(tmp_path: Path):
    # report_path is optional — the in-memory/state path is unchanged without it.
    audit, call_a, _ = _audit_with_two_calls(tmp_path)
    tool = build_submit_report_tool(audit)
    command = tool.invoke(
        {
            "type": "tool_call", "id": "c1", "name": "submit_report",
            "args": {"executive_summary": "x", "findings": [], "iocs": [], "open_questions": []},
        }
    )
    assert command.update["report"]["enforcement"]["confirmed"] == 0
