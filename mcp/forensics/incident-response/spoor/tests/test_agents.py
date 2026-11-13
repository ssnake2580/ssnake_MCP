"""Specialist agents over the shared CaseState.

Agents are exercised with scripted fake models — the point is the wiring
(state schema, tool binding, contract enforcement through the agent loop),
not the LLM. Live-model behavior is verified separately in the live run.
"""

import json
from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.agents import (
    build_ioc_agent,
    build_reporter_agent,
    build_timeline_agent,
    build_triage_agent,
)
from spoor_sift.orchestration.state import CaseState
from spoor_sift.runner import ToolResult

NETSCAN_JSON = json.dumps(
    [{"PID": 666, "Owner": "svch0st.exe", "LocalAddr": "10.0.0.5", "ForeignAddr": "203.0.113.5", "State": "ESTABLISHED"}]
)


class ScriptedChatModel(GenericFakeChatModel):
    """A fake chat model that accepts tool binding (and ignores it)."""

    def bind_tools(self, tools, **kwargs):
        return self


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result

    def run(self, binary: str, args: list[str]) -> ToolResult:
        return self.result


@pytest.fixture
def deps(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return root, audit


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


def test_case_state_declares_the_case_contract():
    keys = set(CaseState.__annotations__)
    assert {
        "messages",
        "remaining_steps",
        "evidence",
        "findings",
        "iocs",
        "open_questions",
        "timeline_ref",
        "report",
    } <= keys


def test_agents_carry_routable_names(deps, workspace):
    # langgraph-supervisor routes by agent name; every specialist must have one.
    root, audit = deps
    runner = FakeRunner(ToolResult(0, "[]", ""))
    model = ScriptedChatModel(messages=iter([]))
    assert build_triage_agent(runner=runner, audit=audit, evidence_root=root, model=model).name == "triage"
    assert build_ioc_agent(runner=runner, audit=audit, evidence_root=root, model=model).name == "ioc_correlation"
    assert build_reporter_agent(audit=audit, model=model).name == "reporter"
    timeline = build_timeline_agent(
        runner=runner, audit=audit, evidence_root=root, workspace_root=workspace, model=model
    )
    assert timeline.name == "timeline"


def test_timeline_agent_slices_through_the_audited_spine(deps, workspace):
    # The timeline specialist queries the super-timeline via the audited core.
    root, audit = deps
    (workspace / "case001.plaso").write_bytes(b"fake plaso store")
    psort_csv = (
        "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
        "2020-09-19T02:19:33+00:00,Event Time,EVT,WinEVTX,RDP logon from 194.61.24.102,winevtx,Security.evtx,-\n"
    )
    scripted = ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "psort_query",
                            "id": "call_1",
                            "type": "tool_call",
                            "args": {"plaso_name": "case001.plaso", "max_events": 50},
                        }
                    ],
                ),
                AIMessage(content="Pivot found: RDP logon 02:19:33."),
            ]
        )
    )
    timeline = build_timeline_agent(
        runner=FakeRunner(ToolResult(0, psort_csv, "")),
        audit=audit, evidence_root=root, workspace_root=workspace, model=scripted,
    )

    result = timeline.invoke({"messages": [HumanMessage("Slice the timeline around triage pivots.")]})

    records = audit.records()
    assert [r.tool for r in records] == ["psort_query"]
    tool_message = next(m for m in result["messages"] if m.type == "tool")
    assert records[0].tool_call_id in tool_message.content
    assert audit.verify().ok


def test_reporter_agent_enforces_contract_through_the_loop(deps):
    # The reporter submits one real citation and one fabricated one; the state it
    # returns must carry the ENFORCED report — fabrication downgraded in code.
    root, audit = deps
    real = audit.append(tool="vol_pslist", args={}, exit_code=0, stdout="{}").tool_call_id

    scripted = ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "submit_report",
                            "id": "call_1",
                            "type": "tool_call",
                            "args": {
                                "executive_summary": "Compromise confirmed.",
                                "findings": [
                                    {"claim": "svch0st.exe running (PID 666)", "status": "confirmed", "tool_call_id": real},
                                    {"claim": "C2 beaconing", "status": "confirmed", "tool_call_id": "f" * 64},
                                ],
                                "iocs": [{"type": "process", "value": "svch0st.exe", "tool_call_id": real}],
                                "open_questions": [],
                            },
                        }
                    ],
                ),
                AIMessage(content="Report submitted."),
            ]
        )
    )
    reporter = build_reporter_agent(audit=audit, model=scripted)

    result = reporter.invoke({"messages": [HumanMessage("Compile the incident report.")]})

    assert result["report"]["enforcement"]["downgraded"] == 1
    assert result["findings"][0]["status"] == "confirmed"
    assert result["findings"][1]["status"] == "inferred"
    assert result["iocs"][0]["value"] == "svch0st.exe"
    assert audit.verify().ok


def test_ioc_agent_runs_audited_memory_tools(deps):
    # The IOC agent's tool calls flow through the same path-jailed, audited core.
    root, audit = deps
    scripted = ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "vol_netscan",
                            "id": "call_1",
                            "type": "tool_call",
                            "args": {"memory_image": "mem.raw"},
                        }
                    ],
                ),
                AIMessage(content="IOC extraction complete: 203.0.113.5."),
            ]
        )
    )
    ioc = build_ioc_agent(
        runner=FakeRunner(ToolResult(0, NETSCAN_JSON, "")),
        audit=audit,
        evidence_root=root,
        model=scripted,
    )

    result = ioc.invoke({"messages": [HumanMessage("Extract and cross-reference IOCs.")]})

    records = audit.records()
    assert [r.tool for r in records] == ["vol_netscan"]
    tool_message = next(m for m in result["messages"] if m.type == "tool")
    assert records[0].tool_call_id in tool_message.content
    assert audit.verify().ok
