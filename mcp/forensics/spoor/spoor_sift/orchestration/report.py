"""Confirmed-vs-inferred contract, enforced in code — not in a prompt.

The reporter model proposes a report; this module is the gate that decides what
may be called "confirmed": only a finding citing a tool_call_id that exists in
the *verified* hash-chained audit log keeps that status. The model cannot talk
its way past this — enforcement is architectural, the same philosophy as the
guardrails.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal

from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool, InjectedToolCallId, tool
from langgraph.types import Command
from pydantic import BaseModel, Field

from spoor_sift.audit import AuditLog


def enforce_citation_contract(report: dict, audit: AuditLog) -> dict:
    """Return a new report with the citation contract applied.

    Adds an ``enforcement`` summary recording the chain status and how many
    findings were confirmed / inferred / downgraded.
    """
    chain = audit.verify()
    known = {record.tool_call_id for record in audit.records()}

    findings = [dict(f) for f in report.get("findings", [])]
    enforced = {**report, "findings": findings}

    summary = {"audit_chain_ok": chain.ok, "confirmed": 0, "inferred": 0, "downgraded": 0}
    for finding in findings:
        if finding.get("status") == "confirmed":
            if chain.ok:
                reason = _citation_violation(finding, known)
            else:
                reason = (
                    f"audit chain verification FAILED ({chain.reason}) — "
                    "no finding can be confirmed against an untrusted trail"
                )
            if reason is not None:
                finding["status"] = "inferred"
                finding["downgraded_reason"] = reason
                summary["downgraded"] += 1

        if finding.get("status") == "confirmed":
            summary["confirmed"] += 1
        else:
            summary["inferred"] += 1

    enforced["enforcement"] = summary
    return enforced


def _citation_violation(finding: dict, known: set[str]) -> str | None:
    """Why this confirmed finding fails the contract, or None if it holds."""
    cited = finding.get("tool_call_id")
    if not cited:
        return "no tool_call_id citation — a confirmed finding must cite the tool execution that backs it"
    if cited not in known:
        return (
            f"cited tool_call_id {str(cited)[:16]}… not found in the audit log — "
            "possible fabricated citation"
        )
    return None


class FindingIn(BaseModel):
    claim: str = Field(description="One specific, falsifiable statement about the case.")
    status: Literal["confirmed", "inferred"] = Field(
        description="'confirmed' ONLY when backed by a tool_call_id citation; otherwise 'inferred'."
    )
    tool_call_id: str | None = Field(
        default=None,
        description="The 64-hex tool_call_id from the tool output that backs this claim.",
    )
    evidence_excerpt: str | None = Field(
        default=None, description="Short verbatim quote of the backing tool output."
    )


class IocIn(BaseModel):
    type: Literal["ip", "domain", "url", "hash", "path", "process", "registry", "other"]
    value: str
    tool_call_id: str | None = Field(
        default=None, description="The tool_call_id of the tool output this IOC came from."
    )


def build_submit_report_tool(audit: AuditLog, *, report_path: Path | str | None = None) -> BaseTool:
    """The reporter's only exit: enforce the contract, update state, seal the report.

    If ``report_path`` is given, the enforced report is also written there the
    instant it is produced — so the case's deliverable survives even if the graph
    later fails to finish (e.g. the supervisor's wrap-up call erroring out). The
    report is the whole point of the run; it must not depend on a clean exit.
    """

    @tool("submit_report")
    def submit_report(
        executive_summary: str,
        findings: list[FindingIn],
        iocs: list[IocIn],
        open_questions: list[str] | None = None,
        tool_call_id: Annotated[str, InjectedToolCallId] = "",
    ) -> Command:
        """Submit the final incident report (mandatory, exactly once).

        Every 'confirmed' finding MUST cite the tool_call_id of the tool execution
        that backs it. Citations are verified against the tamper-evident audit log;
        unverifiable claims are DOWNGRADED to inferences. Returns the enforced report
        — present THAT in your final answer, never your pre-enforcement draft.
        """
        report = {
            "executive_summary": executive_summary,
            "findings": [f.model_dump() for f in findings],
            "iocs": [i.model_dump() for i in iocs],
            "open_questions": list(open_questions or []),
        }
        enforced = enforce_citation_contract(report, audit)

        # Seal the submission into the chain: the report's own content hash becomes
        # an audited, tamper-evident event.
        sealed = audit.append(
            tool="submit_report",
            args={
                "findings": len(enforced["findings"]),
                "iocs": len(enforced["iocs"]),
                "downgraded": enforced["enforcement"]["downgraded"],
            },
            exit_code=0,
            stdout=json.dumps(enforced, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        )
        enforced["report_audit_id"] = sealed.tool_call_id

        if report_path is not None:
            path = Path(report_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(enforced, indent=2, ensure_ascii=False), encoding="utf-8")

        return Command(
            update={
                "report": enforced,
                "findings": enforced["findings"],
                "iocs": enforced["iocs"],
                "open_questions": enforced["open_questions"],
                "messages": [
                    ToolMessage(
                        json.dumps(enforced, ensure_ascii=False), tool_call_id=tool_call_id
                    )
                ],
            }
        )

    return submit_report
