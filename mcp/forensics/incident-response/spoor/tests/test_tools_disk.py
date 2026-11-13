"""Disk tools (Sleuth Kit): tsk_fls listing and tsk_icat extraction."""

import hashlib
from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import PathJailError
from spoor_sift.runner import RawToolResult, ToolResult
from spoor_sift.tools.base import ToolExecutionError
from spoor_sift.tools.disk import tsk_fls, tsk_icat

FLS_OUTPUT = (
    "d/d 38-144-5:\tWindows\n"
    "r/r 12345-128-1:\tWindows/System32/coreupdate.exe\n"
    "r/r * 10234-128-1:\tUsers/Administrator/Desktop/secret.zip\n"
)

PE_BYTES = b"MZ\x90\x00\x03\x00\x00\x00extracted-binary-content"


class FakeRunner:
    def __init__(self, result=None, raw=None):
        self.result = result
        self.raw = raw
        self.calls: list[tuple[str, str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append(("run", binary, list(args)))
        return self.result

    def run_raw(self, binary: str, args: list[str]) -> RawToolResult:
        self.calls.append(("run_raw", binary, list(args)))
        return self.raw


@pytest.fixture
def roots(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir(), workspace.mkdir()
    (evidence / "disk.dd").write_bytes(b"fake disk image")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return evidence, workspace, audit


# --- tsk_fls -----------------------------------------------------------------

def test_fls_parses_entries_including_deleted(roots):
    evidence, _, audit = roots
    runner = FakeRunner(result=ToolResult(0, FLS_OUTPUT, ""))

    result = tsk_fls("disk.dd", runner=runner, audit=audit, evidence_root=evidence)

    assert result["entry_count"] == 3
    directory, exe, deleted = result["entries"]
    assert directory == {"type": "d/d", "inode": "38-144-5", "name": "Windows", "deleted": False}
    assert exe["name"] == "Windows/System32/coreupdate.exe"
    assert exe["deleted"] is False
    assert deleted["name"] == "Users/Administrator/Desktop/secret.zip"
    assert deleted["deleted"] is True
    kind, binary, args = runner.calls[0]
    assert (kind, binary) == ("run", "fls")
    assert args[0:2] == ["-p", "-r"]  # full paths, recursive by default
    assert audit.records()[-1].tool == "tsk_fls"
    assert audit.verify().ok


def test_fls_offset_and_inode_are_passed_through(roots):
    evidence, _, audit = roots
    runner = FakeRunner(result=ToolResult(0, "", ""))

    tsk_fls(
        "disk.dd", offset=206848, inode="38-144-5",
        runner=runner, audit=audit, evidence_root=evidence,
    )

    _, _, args = runner.calls[0]
    assert ["-o", "206848"] == args[2:4]
    assert args[-1] == "38-144-5"  # inode comes after the image path


# --- tsk_icat ----------------------------------------------------------------

def test_icat_extracts_to_workspace_with_chain_of_custody(roots):
    evidence, workspace, audit = roots
    runner = FakeRunner(raw=RawToolResult(0, PE_BYTES, ""))

    result = tsk_icat(
        "disk.dd", "12345-128-1", "coreupdate.exe.extracted",
        runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
    )

    extracted = workspace / "coreupdate.exe.extracted"
    assert extracted.read_bytes() == PE_BYTES
    assert result["sha256"] == hashlib.sha256(PE_BYTES).hexdigest()
    assert result["size"] == len(PE_BYTES)
    assert result["extracted_to"] == str(extracted)
    # the audit record's stdout hash IS the extracted content's hash — custody sealed
    record = audit.records()[-1]
    assert record.tool == "tsk_icat"
    assert record.stdout_sha256 == result["sha256"]
    assert audit.verify().ok


def test_icat_output_name_is_jailed_to_the_workspace(roots):
    evidence, workspace, audit = roots
    runner = FakeRunner(raw=RawToolResult(0, PE_BYTES, ""))

    with pytest.raises(PathJailError):
        tsk_icat(
            "disk.dd", "12345-128-1", "../evidence/overwrite.bin",
            runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
        )
    assert runner.calls == []  # rejected before anything was spawned
    assert audit.records() == []


def test_icat_failure_is_audited_and_raises(roots):
    evidence, workspace, audit = roots
    runner = FakeRunner(raw=RawToolResult(1, b"", "Invalid inode address"))

    with pytest.raises(ToolExecutionError):
        tsk_icat(
            "disk.dd", "99999", "x.bin",
            runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
        )
    record = audit.records()[-1]
    assert record.tool == "tsk_icat"
    assert record.exit_code == 1
    assert not (workspace / "x.bin").exists()  # nothing written on failure
