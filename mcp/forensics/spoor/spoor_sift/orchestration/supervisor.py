"""The Lead Investigator: a supervisor routing the case across the specialists.

One graph, four brains: the lead decides which phase comes next (triage →
IOC/correlation → report), re-routes on failures, and never touches evidence
itself — specialists own the tools. ``output_mode="full_history"`` keeps every
specialist's tool outputs (and their tool_call_ids) in the shared transcript,
which is exactly what the reporter's citation contract feeds on.

Known wart: with a custom ``state_schema``, langgraph 1.2.4 logs
"Task supervisor ... wrote to unknown channel remaining_steps, ignoring it" —
the supervisor's react agent emits its internal step counter upward and the
parent rightly discards it. Benign: step accounting stays correct inside each
agent; nothing case-related is lost.
"""

from __future__ import annotations

from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver
from langgraph_supervisor import create_supervisor

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import ensure_disjoint_roots
from spoor_sift.model import build_chat_model
from spoor_sift.orchestration.agents import (
    build_ioc_agent,
    build_reporter_agent,
    build_timeline_agent,
    build_triage_agent,
)
from spoor_sift.orchestration.gate import build_isolate_host_tool
from spoor_sift.orchestration.state import CaseState

LEAD_INVESTIGATOR_PROMPT = (
    "You are the Lead Investigator on a DFIR case, supervising four specialists:\n"
    "- triage: memory-forensics first pass (processes, network, injected code, command "
    "lines) plus quick-win disk/registry artifacts (file listing, persistence keys).\n"
    "- timeline: builds the plaso super-timeline and slices it around the case pivots to "
    "reconstruct the order of attacker activity.\n"
    "- ioc_correlation: extracts indicators, runs the extract→hash→scan chain on suspect "
    "files, and cross-references indicators across artifacts.\n"
    "- reporter: compiles the final incident report under the citation contract.\n"
    "Sequence the investigation like a senior analyst: triage FIRST; then timeline when "
    "disk/log evidence is available (skip it for memory-only cases); then ioc_correlation "
    "to consolidate indicators; then the reporter LAST — exactly once, after the evidence "
    "work is done. Delegate one phase at a time and read what comes back before routing on.\n"
    "If a specialist reports tool failures or gaps, decide: re-route, send them back with "
    "sharper instructions, or note the gap as an open question for the report.\n"
    "Never answer case questions from your own knowledge — every claim must come from a "
    "specialist's tool-backed work.\n"
    "COMPLETION CONTRACT: the case is complete ONLY after the reporter has returned an "
    "ENFORCED report (a submit_report result with an enforcement summary). You MUST call "
    "transfer_to_reporter before concluding — concluding without the reporter's enforced "
    "report is a protocol violation. Do not send any specialist on more than two passes; "
    "prefer moving the case forward to the reporter over endless re-investigation. After "
    "the reporter returns, summarize the case outcome and stop.\n"
    "CONTAINMENT: you hold one live action, isolate_host — it pauses the case for human "
    "approval before executing. Use it only when the user explicitly asks for containment "
    "or an active threat demands it; record the outcome (approved or rejected) in the case."
)


def build_case_graph(
    *,
    runner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str,
    lead_model=None,
    triage_model=None,
    timeline_model=None,
    ioc_model=None,
    reporter_model=None,
    checkpointer=None,
    report_path: Path | str | None = None,
):
    """Assemble the full investigation graph, compiled with a checkpointer.

    Models are injectable per role (scripted fakes in tests, OpenRouter live);
    the checkpointer (default in-memory) is the prerequisite for resume and the
    human-approval interrupt gate. The workspace (tool artifacts) must be
    disjoint from the read-only evidence tree — enforced here, once, for every
    agent built on top. ``report_path`` makes the reporter persist its enforced
    report to disk at production time (durability against an unclean exit).
    """
    ensure_disjoint_roots(evidence_root, workspace_root)

    triage = build_triage_agent(
        runner=runner, audit=audit, evidence_root=evidence_root, model=triage_model
    )
    timeline = build_timeline_agent(
        runner=runner, audit=audit, evidence_root=evidence_root,
        workspace_root=workspace_root, model=timeline_model,
    )
    ioc = build_ioc_agent(
        runner=runner, audit=audit, evidence_root=evidence_root,
        workspace_root=workspace_root, model=ioc_model,
    )
    reporter = build_reporter_agent(audit=audit, model=reporter_model, report_path=report_path)

    workflow = create_supervisor(
        [triage, timeline, ioc, reporter],
        model=lead_model or build_chat_model("lead"),
        # The lead holds the only live action; it is approval-gated by interrupt().
        tools=[build_isolate_host_tool(audit)],
        prompt=LEAD_INVESTIGATOR_PROMPT,
        state_schema=CaseState,
        output_mode="full_history",
    )
    return workflow.compile(checkpointer=checkpointer or InMemorySaver())
