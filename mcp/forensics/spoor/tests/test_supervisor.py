"""The Lead Investigator graph: supervisor routing over the shared CaseState.

Scripted fake models drive the mechanics (routing, state propagation through
sub-agents, checkpointing) deterministically; live-model autonomy is verified
separately in the live run.
"""

from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.supervisor import build_case_graph
from spoor_sift.runner import ToolResult


class ScriptedChatModel(GenericFakeChatModel):
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
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return root, workspace, audit


def _silent():
    return ScriptedChatModel(messages=iter([]))


def test_case_graph_assembles_the_full_roster(deps):
    root, workspace, audit = deps
    graph = build_case_graph(
        runner=FakeRunner(ToolResult(0, "[]", "")),
        audit=audit,
        evidence_root=root,
        workspace_root=workspace,
        lead_model=_silent(),
        triage_model=_silent(),
        timeline_model=_silent(),
        ioc_model=_silent(),
        reporter_model=_silent(),
    )

    nodes = set(graph.get_graph().nodes)
    assert {"supervisor", "triage", "timeline", "ioc_correlation", "reporter"} <= nodes
    assert graph.checkpointer is not None  # required for resume + the approval gate


def test_supervisor_routes_to_reporter_and_enforced_state_reaches_parent(deps):
    # Supervisor hands the case to the reporter; the reporter submits one real and
    # one fabricated citation; the parent state must come back with the ENFORCED
    # report (fabrication downgraded) — proof that sub-agent state propagates.
    root, workspace, audit = deps
    real = audit.append(tool="vol_pslist", args={}, exit_code=0, stdout="{}").tool_call_id

    lead = ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "transfer_to_reporter", "args": {}, "id": "call_route_1", "type": "tool_call"}
                    ],
                ),
                AIMessage(content="Case closed: report delivered."),
            ]
        )
    )
    reporter = ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "submit_report",
                            "id": "call_submit_1",
                            "type": "tool_call",
                            "args": {
                                "executive_summary": "Compromise confirmed on host.",
                                "findings": [
                                    {"claim": "svch0st.exe running (PID 666)", "status": "confirmed", "tool_call_id": real},
                                    {"claim": "C2 beaconing to 198.51.100.9", "status": "confirmed", "tool_call_id": "f" * 64},
                                ],
                                "iocs": [{"type": "process", "value": "svch0st.exe", "tool_call_id": real}],
                                "open_questions": ["Initial access vector"],
                            },
                        }
                    ],
                ),
                AIMessage(content="Enforced report submitted."),
            ]
        )
    )

    graph = build_case_graph(
        runner=FakeRunner(ToolResult(0, "[]", "")),
        audit=audit,
        evidence_root=root,
        workspace_root=workspace,
        lead_model=lead,
        triage_model=_silent(),
        timeline_model=_silent(),
        ioc_model=_silent(),
        reporter_model=reporter,
    )

    config = {"configurable": {"thread_id": "case-test-1"}}
    result = graph.invoke(
        {
            "messages": [HumanMessage("Investigate mem.raw: is this host compromised?")],
            "evidence": {"memory_image": "mem.raw"},
        },
        config,
    )

    # enforced report propagated from the reporter sub-agent into the parent state
    assert result["report"]["enforcement"] == {
        "audit_chain_ok": True,
        "confirmed": 1,
        "inferred": 1,
        "downgraded": 1,
    }
    assert result["findings"][1]["status"] == "inferred"
    assert result["evidence"] == {"memory_image": "mem.raw"}
    # the run is checkpointed under the thread (resume + approval-gate prerequisite)
    assert graph.get_state(config).values["report"]["report_audit_id"]
    # the trail survived the whole multi-agent run
    assert audit.verify().ok
