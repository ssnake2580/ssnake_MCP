"""Specialist agents. Each owns one phase of the senior-analyst playbook.

The prompts encode the SANS-published triage sequencing *and* explicitly license
self-correction: on a tool failure, reason about the cause and retry rather than
give up. That behavior is emergent (the model decides), surfaced by LangGraph
returning a failed tool call to the model as an error message.

Every agent carries a ``name`` (the supervisor routes by it) and shares the
``CaseState`` schema, so state written by one agent is visible to the next.
"""

from __future__ import annotations

from pathlib import Path

from langgraph.prebuilt import create_react_agent

from spoor_sift.audit import AuditLog
from spoor_sift.model import build_chat_model
from spoor_sift.orchestration.report import build_submit_report_tool
from spoor_sift.orchestration.state import CaseState
from spoor_sift.orchestration.tools import build_tools

TRIAGE_PROMPT = (
    "You are a senior DFIR triage analyst working a Windows host's evidence.\n"
    "Memory first — the standard sequence: list processes (vol_pslist), check the process tree for "
    "anomalous parent/child links (vol_pstree), look for C2 in network connections (vol_netscan), "
    "find injected code (vol_malfind), and inspect launch arguments (vol_cmdline).\n"
    "Then the quick-win disk and registry artifacts when that evidence is available: walk the "
    "filesystem for suspicious or deleted files (tsk_fls — deleted entries are loud signals), and "
    "check persistence with RegRipper (regripper_run: plugin 'run' for autostart keys, "
    "'userassist' for execution history).\n"
    "IMPORTANT: if a tool call FAILS, do not give up — reason about the likely cause, adjust your "
    "approach or arguments, and retry. Persist until you have usable output or have exhausted "
    "sensible options.\n"
    "In your final answer, clearly separate CONFIRMED findings (each backed by specific tool output, "
    "citing its tool_call_id) from INFERENCES, and name the suspicious processes / PIDs you found."
)

TIMELINE_PROMPT = (
    "You are a DFIR timeline analyst. Your craft is the super-timeline: build it once from the "
    "evidence source (log2timeline_run — name the store after the case, e.g. 'case001.plaso'), "
    "then slice it around the pivots the investigation has surfaced (psort_query with a filter "
    "expression like \"date > '2020-09-19 02:00:00' and date < '2020-09-19 03:00:00'\").\n"
    "Anchor on the pivot times mentioned in the conversation (process creation, connection times) "
    "and reconstruct the order of attacker activity: what happened first, what followed, what was "
    "staged or deleted. Slices are capped server-side — narrow your filters instead of paging.\n"
    "If the timeline store already exists, do NOT rebuild it — slice it.\n"
    "IMPORTANT: if a tool call FAILS, reason about the cause, adjust, and retry before moving on.\n"
    "In your final answer, present the attacker timeline in order, each event citing the "
    "tool_call_id of the slice it came from, separating CONFIRMED events from INFERENCES."
)

IOC_PROMPT = (
    "You are a DFIR indicator-extraction and correlation analyst working a Windows host's evidence.\n"
    "Mine the artifacts for indicators of compromise and cross-reference them into a causal chain: "
    "map network endpoints to owning processes (vol_netscan + vol_pslist), tie injected code regions "
    "to PIDs (vol_malfind), and recover staging paths or download URLs from launch arguments "
    "(vol_cmdline). An indicator that appears in two independent artifacts is signal, not noise.\n"
    "When disk evidence is available, run the extraction chain on suspect files: pull the binary "
    "by inode (tsk_icat — its SHA-256 comes back sealed in the audit record), then scan the "
    "extracted artifact with the case rules (yara_scan on the returned extracted_to path; "
    "hash_file works on extracted artifacts too). A file hash corroborated by a YARA hit is a "
    "high-confidence IOC.\n"
    "IMPORTANT: if a tool call FAILS, reason about the cause, adjust, and retry before moving on.\n"
    "In your final answer, list each IOC with its type (ip/domain/url/hash/path/process/registry), "
    "the tool_call_id of the output it came from, and which artifacts corroborate it."
)

REPORTER_PROMPT = (
    "You are the case reporter for a DFIR investigation. Your job is to compile the final "
    "incident report from the investigation conversation above — you do not run evidence tools.\n"
    "Rules of evidence:\n"
    "1. A finding is 'confirmed' ONLY if you can cite the tool_call_id (64-hex) shown in the tool "
    "output that backs it. Everything else — however plausible — is 'inferred'.\n"
    "2. Never invent or guess a tool_call_id. A fabricated citation is worse than an inference.\n"
    "3. You MUST call submit_report exactly once with the full report. The tool verifies every "
    "citation against the tamper-evident audit log and DOWNGRADES anything unverifiable.\n"
    "4. Your final answer must present the ENFORCED report the tool returns — including any "
    "downgrades it applied — never your pre-enforcement draft."
)

# Tool ownership per specialist: triage gets memory + quick-win disk/registry;
# timeline owns plaso; IOC owns the extract -> hash -> scan chain plus the
# memory artifacts it correlates across. pstree stays with triage.
_TRIAGE_TOOL_NAMES = frozenset(
    {"vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline",
     "tsk_fls", "regripper_run"}
)
_TIMELINE_TOOL_NAMES = frozenset({"log2timeline_run", "psort_query"})
_IOC_TOOL_NAMES = frozenset(
    {"vol_pslist", "vol_netscan", "vol_malfind", "vol_cmdline",
     "tsk_icat", "hash_file", "yara_scan"}
)


def _toolset(names, *, runner, audit, evidence_root, workspace_root=None):
    return [
        t
        for t in build_tools(
            runner=runner, audit=audit,
            evidence_root=evidence_root, workspace_root=workspace_root,
        )
        if t.name in names
    ]


def build_triage_agent(*, runner, audit: AuditLog, evidence_root: Path | str, model=None):
    """Build the triage specialist: memory sequence + quick-win disk/registry."""
    model = model or build_chat_model("specialist")
    tools = _toolset(
        _TRIAGE_TOOL_NAMES, runner=runner, audit=audit, evidence_root=evidence_root
    )
    return create_react_agent(
        model, tools, prompt=TRIAGE_PROMPT, name="triage", state_schema=CaseState
    )


def build_timeline_agent(
    *, runner, audit: AuditLog, evidence_root: Path | str,
    workspace_root: Path | str, model=None,
):
    """Build the timeline specialist: super-timeline build + targeted slices."""
    model = model or build_chat_model("specialist")
    tools = _toolset(
        _TIMELINE_TOOL_NAMES, runner=runner, audit=audit,
        evidence_root=evidence_root, workspace_root=workspace_root,
    )
    return create_react_agent(
        model, tools, prompt=TIMELINE_PROMPT, name="timeline", state_schema=CaseState
    )


def build_ioc_agent(
    *, runner, audit: AuditLog, evidence_root: Path | str,
    workspace_root: Path | str | None = None, model=None,
):
    """Build the IOC/correlation specialist: correlate, extract, hash, scan."""
    model = model or build_chat_model("specialist")
    tools = _toolset(
        _IOC_TOOL_NAMES, runner=runner, audit=audit,
        evidence_root=evidence_root, workspace_root=workspace_root,
    )
    return create_react_agent(
        model, tools, prompt=IOC_PROMPT, name="ioc_correlation", state_schema=CaseState
    )


def build_reporter_agent(*, audit: AuditLog, model=None, report_path: Path | str | None = None):
    """Build the reporter: no evidence tools, one exit — the enforcing submit_report.

    ``report_path`` (optional) makes submit_report persist the enforced report to
    disk at production time, so the deliverable survives an unclean graph exit.
    """
    model = model or build_chat_model("specialist")
    return create_react_agent(
        model,
        [build_submit_report_tool(audit, report_path=report_path)],
        prompt=REPORTER_PROMPT,
        name="reporter",
        state_schema=CaseState,
    )
