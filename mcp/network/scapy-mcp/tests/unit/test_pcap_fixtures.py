"""Determinism test for the PCAP fixture generator.

Regenerate every committed fixture and assert byte-identity. A non-deterministic
generator would surface here as a hash mismatch.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO / "tests" / "fixtures"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_fixtures_match_byte_identity() -> None:
    """Regenerate the fixtures and assert byte-identity."""
    expected = {}
    for p in sorted(FIXTURES.glob("*.pcap")):
        expected[p.name] = _sha(p)

    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "gen_pcap_fixtures.py")],
        cwd=REPO, check=True, capture_output=True,
    )
    for name, sha in expected.items():
        assert _sha(FIXTURES / name) == sha, f"{name} is non-deterministic"


def test_provenance_files_exist() -> None:
    for p in sorted(FIXTURES.glob("*.pcap")):
        prov = p.with_suffix(".provenance.json").with_name(
            f"{p.stem}.provenance.json",
        )
        assert prov.exists(), f"missing provenance for {p.name}"
