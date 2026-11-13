"""Disk-forensics tools (Sleuth Kit): list the filesystem, extract files.

``tsk_fls`` walks a filesystem image (deleted entries included — often the
loudest signal on a compromised host). ``tsk_icat`` extracts a file by inode
into the writable workspace, hashing the content in the same breath so the
audit record's stdout hash IS the extracted file's hash — chain of custody by
construction.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import resolve_in_root
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run, audited_run_raw


def _parse_fls_line(line: str) -> dict | None:
    # Format: "r/r [* ]inode:\tpath" — '*' marks a deleted entry.
    line = line.rstrip("\n")
    if not line.strip():
        return None
    head, _, name = line.partition("\t")
    tokens = head.rstrip(":").split()
    if not tokens:
        return None
    entry_type = tokens[0]
    deleted = "*" in tokens[1:-1] or (len(tokens) > 1 and tokens[1] == "*")
    inode = tokens[-1]
    return {"type": entry_type, "inode": inode, "name": name, "deleted": deleted}


def tsk_fls(
    image: str,
    *,
    offset: int | None = None,
    inode: str | None = None,
    recursive: bool = True,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> dict:
    """List filesystem entries from a disk image (Sleuth Kit ``fls``)."""
    image_path = resolve_in_root(evidence_root, image)
    args = ["-p"]
    if recursive:
        args.append("-r")
    if offset is not None:
        args += ["-o", str(offset)]
    args.append(str(image_path))
    if inode is not None:
        args.append(str(inode))
    audit_args = {"image": str(image_path), "offset": offset, "inode": inode}
    result, record = audited_run(
        runner=runner, audit=audit, binary="fls", args=args,
        tool="tsk_fls", audit_args=audit_args,
    )
    entries = [e for e in (_parse_fls_line(line) for line in result.stdout.splitlines()) if e]
    return {
        "tool": "tsk_fls",
        "tool_call_id": record.tool_call_id,
        "entry_count": len(entries),
        "entries": entries,
    }


def tsk_icat(
    image: str,
    inode: str,
    output_name: str,
    *,
    offset: int | None = None,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str,
) -> dict:
    """Extract a file by inode into the workspace (Sleuth Kit ``icat``)."""
    image_path = resolve_in_root(evidence_root, image)
    # Jail the destination BEFORE anything is spawned — fail fast, audit nothing.
    destination = resolve_in_root(workspace_root, output_name)
    args = []
    if offset is not None:
        args += ["-o", str(offset)]
    args += [str(image_path), str(inode)]
    audit_args = {"image": str(image_path), "inode": str(inode), "offset": offset,
                  "output": str(destination)}
    result, record = audited_run_raw(
        runner=runner, audit=audit, binary="icat", args=args,
        tool="tsk_icat", audit_args=audit_args,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(result.stdout)
    return {
        "tool": "tsk_icat",
        "tool_call_id": record.tool_call_id,
        "extracted_to": str(destination),
        "size": len(result.stdout),
        "sha256": hashlib.sha256(result.stdout).hexdigest(),
    }
