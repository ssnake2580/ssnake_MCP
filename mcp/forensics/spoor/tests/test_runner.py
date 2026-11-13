import sys

import pytest

from spoor_sift.guardrails import BinaryNotAllowedError
from spoor_sift.runner import SubprocessRunner, ToolResult


def test_refuses_non_allowlisted_binary():
    runner = SubprocessRunner()
    with pytest.raises(BinaryNotAllowedError):
        runner.run("rm", [])  # rejected by the allow-list before anything is spawned


def test_runs_allowlisted_binary_and_captures_stdout():
    # Inject a resolver mapping the tool name to the Python interpreter, standing in
    # for a forensic binary that isn't installed on this dev host. No shell is used.
    runner = SubprocessRunner(resolve=lambda name: sys.executable)
    result = runner.run("vol", ["-c", "print('processes: 0')"])
    assert isinstance(result, ToolResult)
    assert result.exit_code == 0
    assert "processes: 0" in result.stdout


def test_captures_nonzero_exit_code():
    runner = SubprocessRunner(resolve=lambda name: sys.executable)
    result = runner.run("vol", ["-c", "import sys; sys.exit(3)"])
    assert result.exit_code == 3


def test_run_raw_captures_binary_stdout():
    # icat extracts file CONTENT to stdout — possibly binary that text mode would
    # corrupt. run_raw returns bytes verbatim; stderr stays text for diagnostics.
    runner = SubprocessRunner(resolve=lambda name: sys.executable)
    result = runner.run_raw(
        "icat", ["-c", "import sys; sys.stdout.buffer.write(bytes([0, 255, 77, 90]))"]
    )
    assert result.exit_code == 0
    assert result.stdout == bytes([0, 255, 77, 90])
    assert isinstance(result.stderr, str)


def test_run_raw_refuses_non_allowlisted_binary():
    runner = SubprocessRunner()
    with pytest.raises(BinaryNotAllowedError):
        runner.run_raw("dd", [])
