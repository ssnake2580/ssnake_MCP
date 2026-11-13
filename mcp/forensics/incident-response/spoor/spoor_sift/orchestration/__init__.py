"""LangGraph orchestration: specialist agents over the audited SIFT tools.

A supervisor routes a case to specialists (triage, timeline, IOC, reporter); each
reasons over the structured tool output, and the supervisor handles tool failures
by re-routing/retrying — emergent self-correction, not a fixed pipeline.
"""

from spoor_sift.orchestration.agents import (
    build_ioc_agent,
    build_reporter_agent,
    build_timeline_agent,
    build_triage_agent,
)
from spoor_sift.orchestration.gate import build_isolate_host_tool
from spoor_sift.orchestration.report import build_submit_report_tool, enforce_citation_contract
from spoor_sift.orchestration.state import CaseState
from spoor_sift.orchestration.supervisor import build_case_graph
from spoor_sift.orchestration.tools import build_tools

__all__ = [
    "CaseState",
    "build_case_graph",
    "build_ioc_agent",
    "build_isolate_host_tool",
    "build_reporter_agent",
    "build_submit_report_tool",
    "build_timeline_agent",
    "build_tools",
    "build_triage_agent",
    "enforce_citation_contract",
]
