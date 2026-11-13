import hashlib
import json
import threading
from pathlib import Path

from spoor_sift.audit import AuditLog, GENESIS


def _clock():
    return "2026-06-09T12:00:00+00:00"


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_appends_form_a_hash_chain(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl", clock=_clock)

    r0 = log.append(
        tool="vol_pslist",
        args={"image": "/cases/c1/mem.raw"},
        exit_code=0,
        stdout='{"rows": []}',
    )
    r1 = log.append(
        tool="vol_netscan",
        args={"image": "/cases/c1/mem.raw"},
        exit_code=0,
        stdout='{"conns": 3}',
    )

    # genesis + monotonic sequence
    assert r0.seq == 0
    assert r0.prev_hash == GENESIS
    assert r1.seq == 1

    # output integrity: each record fingerprints its own tool stdout
    assert r0.stdout_sha256 == _sha256('{"rows": []}')
    assert r1.stdout_sha256 == _sha256('{"conns": 3}')

    # chain linkage: each record points back at the previous record's hash
    assert r1.prev_hash == r0.hash
    assert len(r0.hash) == 64 and len(r1.hash) == 64
    assert r0.hash != r1.hash


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _log_with_three(tmp_path: Path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl", clock=_clock)
    log.append(tool="a", args={}, exit_code=0, stdout="x")
    log.append(tool="b", args={"k": 1}, exit_code=0, stdout="y")
    log.append(tool="c", args={}, exit_code=0, stdout="z")
    return log


def test_verify_ok_for_intact_log(tmp_path: Path):
    log = _log_with_three(tmp_path)
    result = log.verify()
    assert result.ok is True
    assert result.broken_seq is None


def test_verify_detects_tampered_field(tmp_path: Path):
    log = _log_with_three(tmp_path)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["exit_code"] = 99  # mutate content without recomputing the chain hash
    lines[1] = json.dumps(rec)
    _rewrite(path, lines)

    result = log.verify()
    assert result.ok is False
    assert result.broken_seq == 1


def test_verify_detects_deleted_record(tmp_path: Path):
    log = _log_with_three(tmp_path)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # excise the middle record
    _rewrite(path, lines)

    result = log.verify()
    assert result.ok is False


def test_records_returns_typed_records_in_order(tmp_path: Path):
    # Public read API: consumers (e.g. the reporter's citation contract) need the
    # recorded calls — notably each record's tool_call_id — without touching privates.
    log = _log_with_three(tmp_path)

    records = log.records()
    assert [r.seq for r in records] == [0, 1, 2]
    assert [r.tool for r in records] == ["a", "b", "c"]
    assert all(len(r.tool_call_id) == 64 for r in records)
    # round-trip: reading back yields exactly what append computed
    assert records[1].args == {"k": 1}


def test_concurrent_appends_keep_chain_intact(tmp_path: Path):
    # A multi-agent run fires tools in parallel; concurrent appends must not corrupt the chain.
    log = AuditLog(tmp_path / "audit.jsonl")

    def worker(i: int) -> None:
        log.append(tool=f"t{i}", args={"i": i}, exit_code=0, stdout=f"out{i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result = log.verify()
    assert result.ok, f"chain broke at seq {result.broken_seq}: {result.reason}"
    assert sum(1 for _ in open(log.path)) == 20
