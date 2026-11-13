"""Architectural guardrails: a filesystem path-jail and a binary allow-list.

These constraints are enforced in code, server-side — not in a model prompt — so
they hold even against a fully jailbroken agent. Two properties:

* **Path-jail**: every evidence path is resolved (symlinks included) and must lie
  within the evidence root; traversal, absolute escapes, and symlink escapes are
  rejected.
* **Allow-list**: only a fixed set of forensic binaries may ever be spawned, so an
  arbitrary shell command is impossible by construction.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable


class PathJailError(ValueError):
    """Raised when a path resolves outside the evidence root."""


class BinaryNotAllowedError(ValueError):
    """Raised when a binary is not on the allow-list (or cannot be found)."""


# Only these executables may be spawned. Curated to the memory -> timeline ->
# disk -> registry -> IOC spine; anything else is rejected before exec.
ALLOWED_BINARIES = frozenset(
    {
        "vol",              # Volatility 3 (memory forensics)
        "log2timeline.py",  # plaso: build a super-timeline
        "psort.py",         # plaso: filter/slice a .plaso store
        "fls",              # Sleuth Kit: list files/inodes
        "icat",             # Sleuth Kit: extract a file by inode
        "rip.pl",           # RegRipper: registry hive plugins
        "yara",             # YARA: signature scan
    }
)


def resolve_in_root(root: Path | str, candidate: str | Path) -> Path:
    """Resolve ``candidate`` and assert it lives within ``root``.

    Symlinks are resolved before the containment check, so a symlink inside the
    root that points outside is rejected. Returns the fully-resolved path.
    """
    root_resolved = Path(root).resolve()
    candidate_path = Path(candidate)
    joined = candidate_path if candidate_path.is_absolute() else root_resolved / candidate_path
    target = joined.resolve()
    if not target.is_relative_to(root_resolved):
        raise PathJailError(
            f"path escapes evidence root: {str(candidate)!r} -> {target} (root: {root_resolved})"
        )
    return target


def resolve_readable(
    candidate: str | Path,
    *,
    evidence_root: Path | str,
    workspace_root: Path | str | None = None,
) -> Path:
    """Resolve a READ-ONLY target in the evidence root, else the workspace.

    Analysis chains extract artifacts into the workspace (icat'd binaries,
    carved hives) and then read them — so read-only targets may live in either
    jail. A relative name is looked up where it EXISTS (evidence first); when it
    exists in neither, the evidence resolution is returned so the tool fails
    with an honest read error. Writes never use this; they stay workspace-only.
    """
    in_evidence: Path | None = None
    try:
        in_evidence = resolve_in_root(evidence_root, candidate)
        if in_evidence.exists():
            return in_evidence
    except PathJailError:
        if workspace_root is None:
            raise
    if workspace_root is not None:
        try:
            in_workspace = resolve_in_root(workspace_root, candidate)
            if in_workspace.exists():
                return in_workspace
        except PathJailError:
            pass
    if in_evidence is not None:
        return in_evidence
    raise PathJailError(
        f"path escapes both jails: {str(candidate)!r} is in neither the evidence root "
        f"({Path(evidence_root).resolve()}) nor the workspace ({Path(workspace_root).resolve()})"
    )


def ensure_disjoint_roots(evidence_root: Path | str, workspace_root: Path | str) -> None:
    """Assert the writable workspace and the read-only evidence tree don't overlap.

    A workspace nested in the evidence tree would let tool outputs contaminate
    evidence (and vice versa would jail outputs with the evidence) — both rejected.
    """
    evidence = Path(evidence_root).resolve()
    workspace = Path(workspace_root).resolve()
    if evidence.is_relative_to(workspace) or workspace.is_relative_to(evidence):
        raise PathJailError(
            f"workspace and evidence roots must be disjoint: evidence={evidence} "
            f"workspace={workspace}"
        )


def is_allowed_binary(name: str) -> bool:
    return name in ALLOWED_BINARIES


def resolve_binary(name: str, *, which: Callable[[str], str | None] = shutil.which) -> str:
    """Return the absolute path of an allow-listed binary, or raise.

    The allow-list is checked *first*, so a non-allow-listed name is rejected
    even when the executable exists on the system.
    """
    if not is_allowed_binary(name):
        raise BinaryNotAllowedError(f"binary not allow-listed: {name!r}")
    path = which(name)
    if path is None:
        raise BinaryNotAllowedError(f"allow-listed binary not found on PATH: {name!r}")
    return path
