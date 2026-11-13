"""Timeline tools (plaso): build a super-timeline, slice it server-side."""

from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import PathJailError
from spoor_sift.runner import ToolResult
from spoor_sift.tools.timeline import log2timeline_run, psort_query

PSORT_CSV = """datetime,timestamp_desc,source,source_long,message,parser,display_name,tag
2020-09-19T02:19:33+00:00,Event Time,EVT,WinEVTX,RDP logon from 194.61.24.102 (Administrator),winevtx,Security.evtx,-
2020-09-19T02:21:47+00:00,Process Start,LOG,Sysmon,powershell.exe -nop -w hidden IWR coreupdate.exe,winevtx,Sysmon.evtx,-
2020-09-19T02:24:06+00:00,Content Modification Time,FILE,NTFS,C:/Windows/System32/coreupdate.exe created,filestat,disk.dd,-
"""


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


@pytest.fixture
def roots(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir(), workspace.mkdir()
    (evidence / "disk.dd").write_bytes(b"fake disk image")
    (workspace / "case001.plaso").write_bytes(b"fake plaso store")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return evidence, workspace, audit


# --- log2timeline_run ---------------------------------------------------------

def test_log2timeline_builds_into_the_workspace(roots):
    evidence, workspace, audit = roots
    runner = FakeRunner(ToolResult(0, "Processing completed.", ""))

    result = log2timeline_run(
        "disk.dd", "timeline.plaso",
        runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
    )

    binary, args = runner.calls[0]
    assert binary == "log2timeline.py"
    assert args == ["--storage-file", str(workspace / "timeline.plaso"), str(evidence / "disk.dd")]
    assert result["plaso_file"] == str(workspace / "timeline.plaso")
    assert audit.records()[-1].tool == "log2timeline_run"
    assert audit.verify().ok


def test_log2timeline_requires_plaso_suffix_and_jails_output(roots):
    evidence, workspace, audit = roots
    runner = FakeRunner(ToolResult(0, "", ""))

    with pytest.raises(ValueError, match=r"\.plaso"):
        log2timeline_run(
            "disk.dd", "timeline.txt",
            runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
        )
    with pytest.raises(PathJailError):
        log2timeline_run(
            "disk.dd", "../evidence/timeline.plaso",
            runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
        )
    assert runner.calls == []


# --- psort_query ----------------------------------------------------------------

def test_psort_parses_events_and_audits(roots):
    _, workspace, audit = roots
    runner = FakeRunner(ToolResult(0, PSORT_CSV, ""))

    result = psort_query("case001.plaso", runner=runner, audit=audit, workspace_root=workspace)

    assert result["event_count"] == 3
    first = result["events"][0]
    assert first["datetime"] == "2020-09-19T02:19:33+00:00"
    assert "RDP logon" in first["message"]
    assert first["source"] == "EVT"
    assert result["truncated"] is False
    binary, args = runner.calls[0]
    assert binary == "psort.py"
    assert args[:3] == ["-q", "-o", "dynamic"]
    assert audit.records()[-1].tool == "psort_query"
    assert audit.verify().ok


def test_psort_filter_expression_is_passed_through(roots):
    _, workspace, audit = roots
    runner = FakeRunner(ToolResult(0, PSORT_CSV, ""))

    psort_query(
        "case001.plaso", filter_expr="date > '2020-09-19 02:00:00'",
        runner=runner, audit=audit, workspace_root=workspace,
    )

    _, args = runner.calls[0]
    assert args[-1] == "date > '2020-09-19 02:00:00'"


def test_psort_caps_events_server_side(roots):
    # Token control (R6): the slice is capped BEFORE it ever reaches the model.
    _, workspace, audit = roots
    runner = FakeRunner(ToolResult(0, PSORT_CSV, ""))

    result = psort_query(
        "case001.plaso", max_events=2,
        runner=runner, audit=audit, workspace_root=workspace,
    )

    assert result["event_count"] == 2
    assert result["total_parsed"] == 3
    assert result["truncated"] is True
