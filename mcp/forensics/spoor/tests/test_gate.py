"""The human-approval gate: state-changing / live-endpoint tools pause the graph.

The gate is architectural — the tool body calls ``interrupt()`` BEFORE any side
effect, so a fully jailbroken model still cannot execute a live action without a
human resume. Both outcomes (approved execution, rejected refusal) land on the
audit chain.
"""

from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.types import Command

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.supervisor import build_case_graph
from spoor_sift.runner import ToolResult


class ScriptedChatModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


class FakeRunner:
    def run(self, binary: str, args: list[str]) -> ToolResult:
        return ToolResult(0, "[]", "")


@pytest.fixture
def deps(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return root, workspace, audit


def _containment_lead():
    return ScriptedChatModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "isolate_host",
                            "id": "call_isolate_1",
                            "type": "tool_call",
                            "args": {"host": "DC01", "reason": "active C2 channel to 194.61.24.102"},
                        }
                    ],
                ),
                AIMessage(content="Containment step resolved."),
            ]
        )
    )


def _graph(root, workspace, audit, lead):
    silent = lambda: ScriptedChatModel(messages=iter([]))  # noqa: E731
    return build_case_graph(
        runner=FakeRunner(),
        audit=audit,
        evidence_root=root,
        workspace_root=workspace,
        lead_model=lead,
        triage_model=silent(),
        timeline_model=silent(),
        ioc_model=silent(),
        reporter_model=silent(),
    )


def test_live_tool_pauses_with_a_describing_interrupt(deps):
    root, workspace, audit = deps
    graph = _graph(root, workspace, audit, _containment_lead())
    config = {"configurable": {"thread_id": "gate-1"}}

    result = graph.invoke({"messages": [HumanMessage("Contain DC01.")]}, config)

    interrupts = result["__interrupt__"]
    payload = interrupts[0].value
    assert payload["action"] == "isolate_host"
    assert payload["args"]["host"] == "DC01"
    assert payload["risk"] == "live_endpoint"
    # nothing executed, nothing audited — the pause happens BEFORE any side effect
    assert audit.records() == []


def test_approved_action_executes_and_is_audited(deps):
    root, workspace, audit = deps
    graph = _graph(root, workspace, audit, _containment_lead())
    config = {"configurable": {"thread_id": "gate-2"}}
    graph.invoke({"messages": [HumanMessage("Contain DC01.")]}, config)

    result = graph.invoke(Command(resume={"decision": "accept"}), config)

    record = audit.records()[-1]
    assert record.tool == "isolate_host"
    assert record.exit_code == 0
    assert record.args["approval"] == "accepted"
    tool_message = next(m for m in result["messages"] if m.type == "tool" and m.name == "isolate_host")
    assert "simulated" in tool_message.content
    assert audit.verify().ok


def test_rejected_action_refuses_and_is_audited(deps):
    root, workspace, audit = deps
    graph = _graph(root, workspace, audit, _containment_lead())
    config = {"configurable": {"thread_id": "gate-3"}}
    graph.invoke({"messages": [HumanMessage("Contain DC01.")]}, config)

    result = graph.invoke(
        Command(resume={"decision": "reject", "reason": "containment out of engagement scope"}),
        config,
    )

    record = audit.records()[-1]
    assert record.tool == "isolate_host"
    assert record.exit_code != 0
    assert record.args["approval"] == "rejected"
    tool_message = next(m for m in result["messages"] if m.type == "tool" and m.name == "isolate_host")
    assert "rejected" in tool_message.content
    # the refusal is data, not a crash — the lead continued to its final message
    assert result["messages"][-1].content == "Containment step resolved."
    assert audit.verify().ok
