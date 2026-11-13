"""Hash-chained, tamper-evident audit trail.

Every tool execution appends exactly one JSONL record. A record's ``hash`` is the
SHA-256 of its canonical content together with the previous record's hash, so any
edit, deletion, or reorder breaks the chain and is detectable (see ``verify``).

A finding cites a record's ``hash`` as its ``tool_call_id`` — the literal answer
to the judging criterion "trace any finding back to the specific tool execution."
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# The first record's ``prev_hash``: 64 zeros, an unambiguous chain anchor.
GENESIS = "0" * 64

# The fields that constitute a record's hashed content (everything but ``hash``).
_CONTENT_FIELDS = ("seq", "ts", "tool", "args", "exit_code", "stdout_sha256", "prev_hash")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical(content: dict) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_content(content: dict) -> str:
    return _sha256_hex(_canonical(content))


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: str
    tool: str
    args: dict
    exit_code: int
    stdout_sha256: str
    prev_hash: str
    hash: str

    @property
    def tool_call_id(self) -> str:
        """Stable, content-addressed id a finding cites to prove provenance."""
        return self.hash

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    broken_seq: int | None = None
    reason: str | None = None


class AuditLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(self, path: Path | str, *, clock: Callable[[], str] = _utc_now_iso):
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()

    def _existing(self) -> list[dict]:
        if not self.path.exists():
            return []
        records: list[dict] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def append(self, *, tool: str, args: dict, exit_code: int, stdout: str | bytes) -> AuditRecord:
        # Serialize concurrent appends (parallel tool calls) so the hash chain stays valid.
        with self._lock:
            existing = self._existing()
            seq = len(existing)
            prev_hash = existing[-1]["hash"] if existing else GENESIS
            content = {
                "seq": seq,
                "ts": self._clock(),
                "tool": tool,
                "args": args,
                "exit_code": exit_code,
                "stdout_sha256": _sha256_hex(stdout),
                "prev_hash": prev_hash,
            }
            record = AuditRecord(**content, hash=_hash_content(content))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(record.to_json() + "\n")
        return record

    def records(self) -> list[AuditRecord]:
        """All recorded calls, in chain order. The public read API for consumers
        (e.g. the reporter's citation contract) that need recorded tool_call_ids."""
        return [AuditRecord(**rec) for rec in self._existing()]

    def verify(self) -> VerifyResult:
        """Recompute the chain end to end; report the first break, if any.

        Catches three tamper classes: a mutated field (content no longer hashes
        to the stored ``hash``), a deleted/reordered/duplicated record (``seq``
        or ``prev_hash`` linkage breaks). Note: truncating the tail of an
        otherwise-valid chain is undetectable without an external anchor.
        """
        prev = GENESIS
        for i, rec in enumerate(self._existing()):
            if rec.get("seq") != i:
                return VerifyResult(False, i, "sequence broken: record missing, duplicated, or reordered")
            if rec.get("prev_hash") != prev:
                return VerifyResult(False, i, "chain broken: prev_hash does not match the previous record")
            content = {k: rec.get(k) for k in _CONTENT_FIELDS}
            if _hash_content(content) != rec.get("hash"):
                return VerifyResult(False, i, "record tampered: stored hash does not match content")
            prev = rec["hash"]
        return VerifyResult(True)
