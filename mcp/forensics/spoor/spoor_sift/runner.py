"""The execution primitive: spawn an allow-listed forensic binary, capture output.

Tools never touch ``subprocess`` directly — they go through a ``ToolRunner`` so the
allow-list gate is unavoidable, and so a dev host with no SIFT binaries (or a test)
can swap in a fixture runner without changing tool code. No shell is ever used:
argv is passed as a list, so shell-injection is impossible by construction.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable, Protocol

from spoor_sift.guardrails import resolve_binary


@dataclass(frozen=True)
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RawToolResult:
    """For tools whose stdout is file CONTENT (icat) — bytes, never text-decoded."""

    exit_code: int
    stdout: bytes
    stderr: str


class ToolRunner(Protocol):
    def run(self, binary: str, args: list[str]) -> ToolResult: ...


class SubprocessRunner:
    """Real runner: resolves the binary through the allow-list, then spawns it."""

    def __init__(
        self,
        *,
        resolve: Callable[[str], str] = resolve_binary,
        timeout: float = 300.0,
    ):
        self._resolve = resolve
        self._timeout = timeout

    def run(self, binary: str, args: list[str]) -> ToolResult:
        path = self._resolve(binary)  # allow-list gate: raises before any spawn
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=self._timeout,
            check=False,
        )
        return ToolResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)

    def run_raw(self, binary: str, args: list[str]) -> RawToolResult:
        """Like ``run`` but stdout stays bytes — for tools that emit file content."""
        path = self._resolve(binary)  # same allow-list gate
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            timeout=self._timeout,
            check=False,
        )
        return RawToolResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr.decode("utf-8", errors="replace"),
        )
