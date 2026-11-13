"""Human-approval gate for state-changing / live-endpoint actions.

Architectural, not prompt-based: the tool body calls ``interrupt()`` BEFORE any
side effect, so even a fully jailbroken model cannot execute a live action —
the graph stops and only a human ``Command(resume=...)`` can continue it. Both
outcomes are sealed into the audit chain: an approved execution records who-
approved-what, a rejection records the refusal and why.

Replay safety: LangGraph re-runs the interrupted task from the top on resume,
so everything before the ``interrupt()`` must be side-effect free — the audit
append and the (simulated) action happen strictly after the decision.

The MVP is read-only end to end; ``isolate_host`` is the simulated live action
that proves the gate's architecture (SPEC §5.3).
"""

from __future__ import annotations

import json

from langchain_core.tools import BaseTool, tool
from langgraph.types import interrupt

from spoor_sift.audit import AuditLog

RISK_LIVE_ENDPOINT = "live_endpoint"


def build_isolate_host_tool(audit: AuditLog) -> BaseTool:
    """Simulated EDR containment — pauses for human approval before acting."""

    @tool("isolate_host")
    def isolate_host(host: str, reason: str) -> dict:
        """[LIVE ACTION — requires human approval] Isolate a host from the network
        (simulated EDR containment). The graph PAUSES until a human approves or
        rejects; use only when the case explicitly calls for containment.
        """
        decision = interrupt(
            {
                "action": "isolate_host",
                "args": {"host": host, "reason": reason},
                "risk": RISK_LIVE_ENDPOINT,
                "instructions": (
                    "Resume with {'decision': 'accept'} to execute, or "
                    "{'decision': 'reject', 'reason': '...'} to refuse. "
                    "Optionally pass edited 'args'."
                ),
            }
        )

        if (decision or {}).get("decision") != "accept":
            human_reason = (decision or {}).get("reason") or "no reason given"
            record = audit.append(
                tool="isolate_host",
                args={"host": host, "reason": reason, "approval": "rejected",
                      "human_reason": human_reason},
                exit_code=1,
                stdout="",
            )
            return {
                "error": f"action rejected by human approver: {human_reason}",
                "approval": "rejected",
                "tool_call_id": record.tool_call_id,
                "hint": "Do not retry without new case facts; note the refusal in the report.",
            }

        args = (decision.get("args") or {"host": host, "reason": reason})
        outcome = {"isolated": args.get("host", host), "simulated": True}
        record = audit.append(
            tool="isolate_host",
            args={**args, "approval": "accepted"},
            exit_code=0,
            stdout=json.dumps(outcome, sort_keys=True),
        )
        return {**outcome, "approval": "accepted", "tool_call_id": record.tool_call_id}

    return isolate_host
