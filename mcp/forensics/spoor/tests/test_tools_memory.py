import json
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import PathJailError
from spoor_sift.runner import ToolResult
from spoor_sift.tools.base import ToolExecutionError
from spoor_sift.tools.memory import (
    vol_cmdline,
    vol_malfind,
    vol_netscan,
    vol_pslist,
    vol_pstree,
)

# A representative slice of Volatility 3 `windows.pslist -r json` output: a flat
# list of column-keyed rows. Includes a deliberately suspicious `svch0st.exe`.
PSLIST_JSON = json.dumps(
    [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": 4337664,
         "Threads": 129, "Handles": None, "SessionId": None, "Wow64": False,
         "CreateTime": "2024-01-15T08:00:00+00:00", "ExitTime": None, "__children": []},
        {"PID": 372, "PPID": 4, "ImageFileName": "smss.exe", "Offset(V)": 12345,
         "Threads": 2, "Handles": 30, "SessionId": None, "Wow64": False,
         "CreateTime": "2024-01-15T08:00:01+00:00", "ExitTime": None, "__children": []},
        {"PID": 666, "PPID": 372, "ImageFileName": "svch0st.exe", "Offset(V)": 99999,
         "Threads": 5, "Handles": 80, "SessionId": 1, "Wow64": True,
         "CreateTime": "2024-01-15T09:13:37+00:00", "ExitTime": None, "__children": []},
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
def evidence_root(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake memory image")
    return root


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-09T12:00:00+00:00")


def test_pslist_parses_processes_into_structured_output(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    out = vol_pslist("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)

    assert out["process_count"] == 3
    assert [p["pid"] for p in out["processes"]] == [4, 372, 666]
    suspicious = out["processes"][2]
    assert suspicious["name"] == "svch0st.exe"
    assert suspicious["ppid"] == 372
    assert suspicious["wow64"] is True
    assert len(out["tool_call_id"]) == 64


def test_pslist_invokes_vol_with_json_renderer_before_plugin(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    vol_pslist("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)

    binary, args = runner.calls[0]
    assert binary == "vol"
    assert args[:2] == ["-f", str((evidence_root / "mem.raw").resolve())]
    assert args[args.index("-r") + 1] == "json"
    assert args.index("-r") < args.index("windows.pslist")


def test_pslist_audits_the_call_and_links_finding_to_it(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    out = vol_pslist("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)

    assert audit.verify().ok is True
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "vol_pslist"
    assert out["tool_call_id"] == record["hash"]  # finding cites the exact execution


def test_pslist_rejects_path_outside_evidence_root(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    with pytest.raises(PathJailError):
        vol_pslist("../../etc/shadow", runner=runner, audit=audit, evidence_root=evidence_root)
    assert runner.calls == []  # guardrail fires before anything is executed


def test_pslist_raises_on_failure_but_still_audits(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(1, "", "Unsatisfied requirement: not a valid memory image"))
    with pytest.raises(ToolExecutionError):
        vol_pslist("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1  # the failed call is still on the record
    assert json.loads(lines[0])["exit_code"] == 1


PSTREE_JSON = json.dumps([{"PID": 666, "PPID": 372, "ImageFileName": "svch0st.exe", "__children": []}])
NETSCAN_JSON = json.dumps(
    [{"Proto": "TCPv4", "LocalAddr": "10.42.85.10", "LocalPort": 49201, "ForeignAddr": "194.61.24.102",
      "ForeignPort": 443, "State": "ESTABLISHED", "PID": 666, "Owner": "svch0st.exe", "Created": "2024-01-15T09:14:00+00:00"}]
)
MALFIND_JSON = json.dumps(
    [{"PID": 666, "Process": "svch0st.exe", "Start VPN": "0x1f0000", "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS"}]
)
CMDLINE_JSON = json.dumps([{"PID": 666, "Process": "svch0st.exe", "Args": "C:\\Windows\\System32\\svch0st.exe -k netsvcs"}])


def test_pstree_uses_pstree_plugin(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, PSTREE_JSON, ""))
    out = vol_pstree("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)
    assert runner.calls[0][1][-1] == "windows.pstree"
    assert out["processes"][0]["pid"] == 666
    assert len(out["tool_call_id"]) == 64


def test_netscan_normalizes_connections(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, NETSCAN_JSON, ""))
    out = vol_netscan("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)
    assert runner.calls[0][1][-1] == "windows.netscan"
    conn = out["connections"][0]
    assert conn["foreign_addr"] == "194.61.24.102" and conn["pid"] == 666
    assert out["connection_count"] == 1


def test_malfind_normalizes_injections(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, MALFIND_JSON, ""))
    out = vol_malfind("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)
    assert runner.calls[0][1][-1] == "windows.malfind"
    inj = out["injections"][0]
    assert inj["pid"] == 666 and "EXECUTE" in inj["protection"]


def test_cmdline_normalizes_args(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, CMDLINE_JSON, ""))
    out = vol_cmdline("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)
    assert runner.calls[0][1][-1] == "windows.cmdline"
    entry = out["entries"][0]
    assert entry["pid"] == 666 and "svch0st" in entry["args"]


# --- real-scale behaviors (a 2GB image returns thousands of rows) -------------

PSTREE_NESTED_JSON = json.dumps(
    [
        {
            "PID": 4, "PPID": 0, "ImageFileName": "System",
            "__children": [
                {
                    "PID": 372, "PPID": 4, "ImageFileName": "smss.exe",
                    "__children": [
                        {"PID": 666, "PPID": 372, "ImageFileName": "svch0st.exe", "__children": []}
                    ],
                }
            ],
        }
    ]
)


def test_pstree_flattens_nested_children(evidence_root: Path, audit: AuditLog):
    # Real windows.pstree nests rows under __children; every process must surface.
    runner = FakeRunner(ToolResult(0, PSTREE_NESTED_JSON, ""))
    out = vol_pstree("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)

    assert out["process_count"] == 3
    assert {p["pid"] for p in out["processes"]} == {4, 372, 666}
    nested = next(p for p in out["processes"] if p["pid"] == 666)
    assert nested["ppid"] == 372


def _netscan_rows(n: int, *, state: str = "LISTENING") -> list[dict]:
    return [
        {"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 1000 + i,
         "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": state,
         "PID": 4, "Owner": "System", "Created": None}
        for i in range(n)
    ]


def test_netscan_dedupes_pool_scan_duplicates(evidence_root: Path, audit: AuditLog):
    # Pool scanning surfaces the same socket many times; identical tuples collapse.
    row = {"Proto": "TCPv4", "LocalAddr": "10.42.85.10", "LocalPort": 62613,
           "ForeignAddr": "203.78.103.109", "ForeignPort": 443, "State": "ESTABLISHED",
           "PID": 3644, "Owner": "coreupdater.ex", "Created": None}
    runner = FakeRunner(ToolResult(0, json.dumps([row, dict(row), dict(row)]), ""))

    out = vol_netscan("mem.raw", runner=runner, audit=audit, evidence_root=evidence_root)

    assert out["connection_count"] == 1
    assert out["total_scanned"] == 3


def test_netscan_caps_rows_server_side(evidence_root: Path, audit: AuditLog):
    runner = FakeRunner(ToolResult(0, json.dumps(_netscan_rows(500)), ""))

    out = vol_netscan("mem.raw", max_rows=100, runner=runner, audit=audit, evidence_root=evidence_root)

    assert out["connection_count"] == 100
    assert out["truncated"] is True
    assert out["total_scanned"] == 500


def test_netscan_state_filter_is_applied_server_side(evidence_root: Path, audit: AuditLog):
    rows = _netscan_rows(50) + [
        {"Proto": "TCPv4", "LocalAddr": "10.42.85.10", "LocalPort": 62613,
         "ForeignAddr": "203.78.103.109", "ForeignPort": 443, "State": "ESTABLISHED",
         "PID": 3644, "Owner": "coreupdater.ex", "Created": None}
    ]
    runner = FakeRunner(ToolResult(0, json.dumps(rows), ""))

    out = vol_netscan(
        "mem.raw", state="ESTABLISHED", runner=runner, audit=audit, evidence_root=evidence_root
    )

    assert out["connection_count"] == 1
    assert out["connections"][0]["foreign_addr"] == "203.78.103.109"


def test_pslist_caps_rows_server_side(evidence_root: Path, audit: AuditLog):
    rows = [
        {"PID": i, "PPID": 0, "ImageFileName": f"p{i}.exe", "__children": []}
        for i in range(50)
    ]
    runner = FakeRunner(ToolResult(0, json.dumps(rows), ""))

    out = vol_pslist("mem.raw", max_rows=10, runner=runner, audit=audit, evidence_root=evidence_root)

    assert out["process_count"] == 10
    assert out["truncated"] is True
    assert out["total_scanned"] == 50
