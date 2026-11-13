import json
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.runner import ToolResult
from spoor_sift.server import build_server, build_server_from_env

PSLIST_JSON = json.dumps(
    [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 372, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 666, "PPID": 372, "ImageFileName": "svch0st.exe"},
    ]
)


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


def _payload(result) -> dict:
    """Unwrap FastMCP's call_tool envelope: (content, structured) | content | dict.

    Plain-dict returns are wrapped as {"result": payload} in structured content.
    """
    if isinstance(result, tuple):
        structured = result[1]
        return structured.get("result", structured)
    if isinstance(result, dict):
        return result
    return json.loads(result[0].text)


@pytest.fixture
def server(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake memory image")
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-09T12:00:00+00:00")
    return build_server(runner=runner, audit=audit, evidence_root=root)


@pytest.fixture
def full_server(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake memory image")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = FakeRunner(ToolResult(0, PSLIST_JSON, ""))
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-09T12:00:00+00:00")
    return build_server(
        runner=runner, audit=audit, evidence_root=root, workspace_root=workspace
    )


async def test_server_registers_vol_pslist(server):
    tools = await server.list_tools()
    by_name = {t.name: t for t in tools}
    assert "vol_pslist" in by_name
    assert by_name["vol_pslist"].description  # docstring surfaced to MCP clients


async def test_server_tool_delegates_to_core(server):
    result = await server.call_tool("vol_pslist", {"memory_image": "mem.raw"})
    payload = _payload(result)
    assert payload["process_count"] == 3
    assert len(payload["tool_call_id"]) == 64


def test_build_server_from_env_requires_evidence_root(monkeypatch):
    monkeypatch.delenv("EVIDENCE_ROOT", raising=False)
    with pytest.raises(RuntimeError):
        build_server_from_env()


async def test_server_registers_all_memory_tools(server):
    names = {t.name for t in await server.list_tools()}
    assert {"vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline"} <= names


async def test_full_server_exposes_the_complete_dozen(full_server):
    names = {t.name for t in await full_server.list_tools()}
    assert names == {
        "vol_pslist", "vol_pstree", "vol_netscan", "vol_malfind", "vol_cmdline",
        "tsk_fls", "tsk_icat", "regripper_run", "hash_file", "yara_scan",
        "log2timeline_run", "psort_query",
    }


async def test_full_server_runs_an_in_process_tool_end_to_end(full_server, tmp_path: Path):
    # hash_file goes through no subprocess at all — pure core + audit.
    (tmp_path / "evidence" / "coreupdate.exe").write_bytes(b"MZ-fake")

    result = await full_server.call_tool("hash_file", {"path": "coreupdate.exe"})
    payload = _payload(result)

    assert payload["size"] == 7
    assert len(payload["sha256"]) == 64
    assert len(payload["tool_call_id"]) == 64


async def test_full_server_surfaces_typed_optional_params(full_server):
    # The MCP schema must carry the typed optional args (offset, max_events, ...)
    tools = {t.name: t for t in await full_server.list_tools()}
    fls_props = tools["tsk_fls"].inputSchema["properties"]
    assert {"image", "offset", "inode", "recursive"} <= set(fls_props)
    psort_props = tools["psort_query"].inputSchema["properties"]
    assert {"plaso_name", "filter_expr", "max_events"} <= set(psort_props)
