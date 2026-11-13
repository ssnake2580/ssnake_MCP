"""Registry tool: RegRipper plugin runs against a hive."""

from pathlib import Path

import pytest

from spoor_sift.audit import AuditLog
from spoor_sift.runner import ToolResult
from spoor_sift.tools.registry import regripper_run

RUN_KEY_OUTPUT = """run v.20200511
(Software) [Autostart] Get autostart key contents from Software hive

Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time 2020-09-19 02:24:40 (UTC)
  CoreUpdater - C:\\Windows\\System32\\coreupdate.exe -install
"""


class FakeRunner:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, binary: str, args: list[str]) -> ToolResult:
        self.calls.append((binary, list(args)))
        return self.result


@pytest.fixture
def deps(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "SOFTWARE").write_bytes(b"regf-fake-hive")
    audit = AuditLog(tmp_path / "audit.jsonl", clock=lambda: "2026-06-10T00:00:00+00:00")
    return evidence, audit


def test_regripper_runs_plugin_against_jailed_hive(deps):
    evidence, audit = deps
    runner = FakeRunner(ToolResult(0, RUN_KEY_OUTPUT, ""))

    result = regripper_run("SOFTWARE", "run", runner=runner, audit=audit, evidence_root=evidence)

    assert result["plugin"] == "run"
    assert "CoreUpdater" in result["text"]
    binary, args = runner.calls[0]
    assert binary == "rip.pl"
    assert args == ["-r", str(evidence / "SOFTWARE"), "-p", "run"]
    record = audit.records()[-1]
    assert record.tool == "regripper_run"
    assert record.args["plugin"] == "run"
    assert audit.verify().ok


def test_regripper_reads_an_extracted_workspace_hive(deps, tmp_path: Path):
    # Real disk images require extracting the hive first (icat -> workspace);
    # RegRipper must therefore accept hives from either read-only-treated jail.
    evidence, audit = deps
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "SOFTWARE.extracted").write_bytes(b"regf-extracted-hive")
    runner = FakeRunner(ToolResult(0, RUN_KEY_OUTPUT, ""))

    result = regripper_run(
        "SOFTWARE.extracted", "run",
        runner=runner, audit=audit, evidence_root=evidence, workspace_root=workspace,
    )

    assert "CoreUpdater" in result["text"]
    _, args = runner.calls[0]
    assert args[1] == str(workspace / "SOFTWARE.extracted")


def test_regripper_rejects_malformed_plugin_names(deps):
    # argv-list execution already makes injection impossible; the name check
    # exists to fail fast with an actionable error instead of a RegRipper stack.
    evidence, audit = deps
    runner = FakeRunner(ToolResult(0, "", ""))

    with pytest.raises(ValueError, match="plugin"):
        regripper_run("SOFTWARE", "run; rm -rf /", runner=runner, audit=audit, evidence_root=evidence)
    assert runner.calls == []
    assert audit.records() == []
