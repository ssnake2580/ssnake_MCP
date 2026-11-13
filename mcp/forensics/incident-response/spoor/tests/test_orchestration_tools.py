import json
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.tools import build_tools
from spoor_sift.runner import ToolResult

PSLIST_JSON = json.dumps(
    [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 666, "PPID": 4, "ImageFileName": "svch0st.exe"},
    ]
)


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


@pytest.fixture
def deps(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return root, audit


def test_build_tools_exposes_memory_tools(deps):
    root, audit = deps
    tools = build_tools(runner=FakeRunner(ToolResult(0, PSLIST_JSON, "")), audit=audit, evidence_root=root)
    names = {t.name for t in tools}
    assert {"vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline"} <= names
    # tools carry descriptions for the agent's tool selection
    assert all(t.description for t in tools)


def test_build_tools_without_workspace_covers_evidence_only_tools(deps):
    root, audit = deps
    tools = build_tools(runner=FakeRunner(ToolResult(0, "[]", "")), audit=audit, evidence_root=root)
    names = {t.name for t in tools}
    assert {"tsk_fls", "regripper_run", "hash_file"} <= names
    # artifact-producing tools need a writable workspace — absent without one
    assert names.isdisjoint({"tsk_icat", "yara_scan", "log2timeline_run", "psort_query"})


def test_build_tools_with_workspace_exposes_the_full_dozen(deps, tmp_path: Path):
    root, audit = deps
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = build_tools(
        runner=FakeRunner(ToolResult(0, "[]", "")),
        audit=audit, evidence_root=root, workspace_root=workspace,
    )
    names = {t.name for t in tools}
    assert names == {
        "vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline",
        "tsk_fls", "tsk_icat", "regripper_run", "hash_file", "yara_scan",
        "log2timeline_run", "psort_query",
    }


def test_guardrail_violations_return_error_dicts_for_self_correction(deps, tmp_path: Path):
    # Bad args (jail escapes, malformed names) must come back as readable data —
    # the agent reasons and retries; the graph never crashes.
    root, audit = deps
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = {
        t.name: t
        for t in build_tools(
            runner=FakeRunner(ToolResult(0, "[]", "")),
            audit=audit, evidence_root=root, workspace_root=workspace,
        )
    }

    escape = tools["hash_file"].invoke({"path": "../../etc/passwd"})
    assert "error" in escape and "escape" in escape["error"]

    bad_plugin = tools["regripper_run"].invoke({"hive": "SOFTWARE", "plugin": "run; rm"})
    assert "error" in bad_plugin and "plugin" in bad_plugin["error"]


def test_tool_invocation_delegates_to_audited_core(deps):
    root, audit = deps
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    tools = build_tools(runner=runner, audit=audit, evidence_root=root)
    pslist = next(t for t in tools if t.name == "vol_pslist")

    result = pslist.invoke({"memory_image": "mem.raw"})
    assert result["process_count"] == 2
    assert len(result["tool_call_id"]) == 64  # it went through the audited core
    assert runner.calls[0][1][-1] == "windows.pslist"


def test_tool_failure_returns_error_dict_not_raises(deps):
    # On failure the tool must return a readable error (so the agent can self-correct),
    # NOT raise (which would crash the graph). The failed call is still audited.
    root, audit = deps
    runner = FakeRunner(ToolResult(1, "", "invalid memory image header"))
    tools = build_tools(runner=runner, audit=audit, evidence_root=root)
    pslist = next(t for t in tools if t.name == "vol_pslist")

    result = pslist.invoke({"memory_image": "mem.raw"})
    assert "error" in result
    assert "invalid memory image header" in result["error"]
    assert audit.verify().ok
    assert sum(1 for _ in open(audit.path)) == 1  # the failure is on the record
