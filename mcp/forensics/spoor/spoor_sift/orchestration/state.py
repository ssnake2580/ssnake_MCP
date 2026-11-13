"""The shared case state every agent works over.

Extends LangGraph's ``AgentState`` (messages + remaining_steps) with the case
file. Replace semantics on every key, with a single-writer rule: only the
reporter's ``submit_report`` tool writes findings/iocs/report — and it writes
post-enforcement data only, so state never carries an unverified "confirmed".
"""

from __future__ import annotations

from typing import NotRequired

from langgraph.prebuilt.chat_agent_executor import AgentState


class CaseState(AgentState):
    evidence: NotRequired[dict[str, str]]
    findings: NotRequired[list[dict]]
    iocs: NotRequired[list[dict]]
    open_questions: NotRequired[list[str]]
    timeline_ref: NotRequired[str | None]
    report: NotRequired[dict | None]
