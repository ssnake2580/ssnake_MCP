from pathlib import Path

import pytest

from spoor_sift.guardrails import (
    BinaryNotAllowedError,
    PathJailError,
    ensure_disjoint_roots,
    is_allowed_binary,
    resolve_binary,
    resolve_in_root,
)


@pytest.fixture
def evidence_root(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "mem.raw").write_bytes(b"fake memory image")
    return root


# --- path jail -------------------------------------------------------------

def test_accepts_path_inside_root(evidence_root: Path):
    resolved = resolve_in_root(evidence_root, "mem.raw")
    assert resolved == (evidence_root / "mem.raw").resolve()


def test_rejects_parent_traversal(evidence_root: Path):
    with pytest.raises(PathJailError):
        resolve_in_root(evidence_root, "../../etc/passwd")


def test_rejects_absolute_path_outside_root(evidence_root: Path):
    with pytest.raises(PathJailError):
        resolve_in_root(evidence_root, "/etc/passwd")


def test_rejects_symlink_escape(evidence_root: Path):
    outside = evidence_root.parent / "secret.txt"
    outside.write_text("top secret")
    (evidence_root / "escape").symlink_to(outside)
    with pytest.raises(PathJailError):
        resolve_in_root(evidence_root, "escape")


# --- binary allow-list -----------------------------------------------------

def test_allow_list_membership():
    assert is_allowed_binary("vol") is True
    assert is_allowed_binary("bash") is False
    assert is_allowed_binary("rm") is False


def test_rejects_non_allowlisted_binary_even_if_present():
    # 'rm' exists on the system, but is not allow-listed -> rejected before exec.
    with pytest.raises(BinaryNotAllowedError):
        resolve_binary("rm", which=lambda n: "/bin/rm")


def test_resolves_allowlisted_binary():
    fake_which = lambda n: "/opt/sift/bin/vol" if n == "vol" else None
    assert resolve_binary("vol", which=fake_which) == "/opt/sift/bin/vol"


# --- workspace / evidence separation ----------------------------------------

def test_disjoint_roots_accepted(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir(), workspace.mkdir()
    ensure_disjoint_roots(evidence, workspace)  # no raise


def test_workspace_inside_evidence_rejected(tmp_path: Path):
    # A writable workspace nested in the read-only evidence tree would let tool
    # outputs contaminate the evidence — rejected by construction.
    evidence = tmp_path / "evidence"
    workspace = evidence / "workspace"
    workspace.mkdir(parents=True)
    with pytest.raises(PathJailError):
        ensure_disjoint_roots(evidence, workspace)


def test_evidence_inside_workspace_rejected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    evidence = workspace / "evidence"
    evidence.mkdir(parents=True)
    with pytest.raises(PathJailError):
        ensure_disjoint_roots(evidence, workspace)
