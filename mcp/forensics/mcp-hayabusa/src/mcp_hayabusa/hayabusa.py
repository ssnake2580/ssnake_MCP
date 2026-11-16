"""Thin subprocess wrapper around the Hayabusa CLI binary.

Flags are based on Hayabusa's csv-timeline/json-timeline reference
(https://yamato-security.github.io/hayabusa/commands/dfir-timeline/).
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

OutputFormat = Literal["csv", "json", "jsonl"]

PREVIEW_RECORD_LIMIT = 20
RULE_LIST_LIMIT = 50


class HayabusaError(RuntimeError):
    """Raised when the hayabusa binary cannot be found, or a scan fails/times out."""


def resolve_binary() -> str:
    """Locate the hayabusa executable.

    Checks the HAYABUSA_BIN env var first (either a full path or a name to
    resolve on PATH), then falls back to `hayabusa`/`hayabusa.exe` on PATH.
    """
    configured = os.environ.get("HAYABUSA_BIN")
    if configured:
        resolved = configured if Path(configured).exists() else shutil.which(configured)
        if not resolved:
            raise HayabusaError(
                f"HAYABUSA_BIN is set to '{configured}' but it does not exist "
                "and cannot be resolved on PATH."
            )
        return resolved

    found = shutil.which("hayabusa") or shutil.which("hayabusa.exe")
    if not found:
        raise HayabusaError(
            "Could not find the hayabusa binary. Install it from "
            "https://github.com/Yamato-Security/hayabusa, ensure it is on PATH, "
            "or set the HAYABUSA_BIN environment variable to its full path."
        )
    return found


@dataclass
class ScanResult:
    command: list[str]
    output_format: OutputFormat
    output_path: str
    returncode: int
    stdout_tail: str
    stderr_tail: str
    record_count: int | None = None
    preview: list[dict] | dict | None = None
    level_counts: dict[str, int] | None = None
    top_rules: list[dict] | None = None


def _tail(text: str, lines: int = 40) -> str:
    return "\n".join(text.splitlines()[-lines:])


def scan(
    target: str,
    *,
    is_file: bool = False,
    output_format: OutputFormat = "json",
    rules_dir: str | None = None,
    rule_filter: str | None = None,
    min_level: str | None = None,
    utc: bool = False,
    output_path: str | None = None,
    max_results: int | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 1800,
) -> ScanResult:
    """Run `hayabusa csv-timeline`/`json-timeline` against an .evtx file or directory.

    Always passes -w/-q so the scan runs non-interactively (no rule-config
    wizard, no launch banner), which is required since there is no stdin/tty
    when invoked from an MCP tool call.

    `rule_filter`, if given, restricts which rules are loaded to those whose
    rule file text case-insensitively contains the string (see
    `_build_rule_filter_dir`) — Hayabusa has no native free-text rule filter.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise HayabusaError(f"Target path does not exist: {target}")

    binary = resolve_binary()
    subcommand = "csv-timeline" if output_format == "csv" else "json-timeline"

    # hayabusa refuses to write to a pre-existing output file (without -C/--clobber),
    # so use a fresh temp directory rather than tempfile.mkstemp, which creates the file.
    cleanup_dir: str | None = None
    if output_path is None:
        suffix = ".csv" if output_format == "csv" else ".json"
        cleanup_dir = tempfile.mkdtemp(prefix="hayabusa_")
        output_path = str(Path(cleanup_dir) / f"output{suffix}")

    effective_rules_dir = rules_dir
    filter_dir_cleanup: str | None = None
    if rule_filter:
        base = _resolve_rules_dir(rules_dir, binary=binary)
        filter_dir = _build_rule_filter_dir(base, rule_filter)
        filter_dir_cleanup = filter_dir
        effective_rules_dir = filter_dir

    command = [binary, subcommand]
    command += ["-f", str(target_path)] if is_file else ["-d", str(target_path)]
    command += ["-o", output_path, "-w", "-q"]
    if effective_rules_dir:
        command += ["-r", effective_rules_dir]
    if min_level:
        command += ["-m", min_level]
    if utc:
        command += ["-U"]
    if output_format == "jsonl":
        command += ["-L"]
    if extra_args:
        command += extra_args

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise HayabusaError(f"Failed to execute hayabusa binary at '{binary}': {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HayabusaError(f"hayabusa scan timed out after {timeout}s") from exc
    finally:
        if filter_dir_cleanup:
            shutil.rmtree(filter_dir_cleanup, ignore_errors=True)

    result = ScanResult(
        command=command,
        output_format=output_format,
        output_path=output_path,
        returncode=proc.returncode,
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
    )

    try:
        if proc.returncode == 0 and Path(output_path).exists():
            _attach_preview(result, max_records=max_results if max_results is not None else PREVIEW_RECORD_LIMIT)
    except OSError as exc:
        raise HayabusaError(
            f"hayabusa exited successfully but its output file at '{output_path}' could not be "
            f"read afterward ({exc}). This can happen if antivirus/endpoint security quarantined "
            "or deleted it — Hayabusa's raw output embeds detection strings (tool/malware names) "
            "that can trigger AV heuristics; consider excluding the output/temp directory from "
            "real-time scanning."
        ) from exc
    finally:
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    return result


def _resolve_rules_dir(rules_dir: str | None, *, binary: str | None = None) -> Path:
    """Resolve a rules directory: `rules_dir` if given, else Hayabusa's own default
    (./rules relative to cwd), falling back to a ./rules directory next to the
    resolved binary (this repo's layout).
    """
    if rules_dir:
        base = Path(rules_dir)
        if not base.is_dir():
            raise HayabusaError(f"rules_dir does not exist or is not a directory: {rules_dir}")
        return base

    cwd_rules = Path.cwd() / "rules"
    if cwd_rules.is_dir():
        return cwd_rules

    if binary is None:
        binary = resolve_binary()
    binary_rules = Path(binary).resolve().parent / "rules"
    if binary_rules.is_dir():
        return binary_rules

    raise HayabusaError(
        "Could not resolve a rules directory; pass rules_dir explicitly (no default "
        "./rules directory found relative to the current directory or the hayabusa binary)."
    )


def _rule_files_matching(base_dir: Path, keyword: str | None) -> list[Path]:
    """Rule files under `base_dir` whose text case-insensitively contains `keyword`
    (all rule files if `keyword` is None), sorted for stable ordering.
    """
    files = sorted(base_dir.rglob("*.yml"))
    if not keyword:
        return files
    needle_lower = keyword.lower()
    return [
        path for path in files if needle_lower in path.read_text(encoding="utf-8", errors="replace").lower()
    ]


def _build_rule_filter_dir(base_dir: Path, needle: str) -> str:
    """Copy rule files under `base_dir` whose text matches `needle` (case-insensitive)
    into a fresh temp directory, and return its path.

    Raises HayabusaError if no rule files match.
    """
    matches = _rule_files_matching(base_dir, needle)
    if not matches:
        raise HayabusaError(f"No rules under {base_dir} matched rule_filter={needle!r}")

    filter_dir = tempfile.mkdtemp(prefix="hayabusa_rule_filter_")
    for i, path in enumerate(matches):
        shutil.copy2(path, Path(filter_dir) / f"{i:04d}_{path.name}")
    return filter_dir


@dataclass
class RuleInfo:
    path: str
    id: str | None = None
    title: str | None = None
    level: str | None = None
    status: str | None = None
    description: str | None = None
    author: str | None = None
    tags: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)


def _parse_rule_file(path: Path, base: Path) -> RuleInfo | None:
    """Parse one Sigma rule YAML file into a RuleInfo, or None if it isn't a valid
    Sigma detection rule (invalid YAML, or no `detection` block).
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict) or "detection" not in data:
        return None
    return RuleInfo(
        path=path.relative_to(base).as_posix(),
        id=data.get("id"),
        title=data.get("title"),
        level=data.get("level"),
        status=data.get("status"),
        description=data.get("description"),
        author=data.get("author"),
        tags=data.get("tags") or [],
        logsource=data.get("logsource") or {},
    )


def list_rules(
    rules_dir: str | None = None,
    keyword: str | None = None,
    max_results: int | None = None,
) -> tuple[list[RuleInfo], int]:
    """List Hayabusa/Sigma detection rules under `rules_dir` (default: Hayabusa's
    bundled ./rules), optionally filtered to those whose rule file text
    case-insensitively contains `keyword` — the same matching `scan()` uses for
    `rule_filter`, so a keyword here can be passed straight to `rule_filter` later.

    Returns (rules, total_matched), where `rules` is capped at `max_results`
    (default RULE_LIST_LIMIT) but `total_matched` is the true match count.
    """
    base = _resolve_rules_dir(rules_dir)
    matches = _rule_files_matching(base, keyword)
    limit = max_results if max_results is not None else RULE_LIST_LIMIT

    rules = []
    for path in matches:
        if len(rules) >= limit:
            break
        rule = _parse_rule_file(path, base)
        if rule is not None:
            rules.append(rule)
    return rules, len(matches)


_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _technique_ids(tags: list[str]) -> list[str]:
    """Extract ATT&CK technique IDs (e.g. 'T1003', 'T1003.001') from a rule's Sigma
    `tags`, which encode them as e.g. 'attack.t1003.001'. Tactic tags like
    'attack.credential-access' don't match this shape and are ignored.
    """
    ids = []
    for tag in tags:
        match = _ATTACK_TAG_RE.match(tag.strip())
        if match:
            ids.append(match.group(1).upper())
    return ids


def list_attack_techniques(rules_dir: str | None = None) -> dict[str, list[RuleInfo]]:
    """Group every valid rule under `rules_dir` by ATT&CK technique ID found in its
    tags (see `_technique_ids`). A rule tagged with multiple technique IDs appears
    under each; rules with no technique tag are omitted entirely.

    Unlike list_rules(), this always parses every rule file with no cap and no
    keyword — technique IDs, not individual rules, are the browsable unit here, and
    the full ruleset (thousands of files) is too large to list flatly.

    Returns a dict sorted by technique ID.
    """
    base = _resolve_rules_dir(rules_dir)
    grouped: dict[str, list[RuleInfo]] = {}
    for path in _rule_files_matching(base, None):
        rule = _parse_rule_file(path, base)
        if rule is None:
            continue
        for technique_id in _technique_ids(rule.tags):
            grouped.setdefault(technique_id, []).append(rule)
    return dict(sorted(grouped.items()))


def get_attack_technique_rules(technique_id: str, rules_dir: str | None = None) -> list[RuleInfo]:
    """Rules tagged with a specific ATT&CK technique ID, e.g. 'T1003' or 'T1003.001'
    (case-insensitive). Empty list if none match.
    """
    return list_attack_techniques(rules_dir).get(technique_id.strip().upper(), [])


def read_rule_file(path: str, rules_dir: str | None = None) -> str:
    """Return the raw YAML text of a single rule file at `path` — a posix-style
    path relative to `rules_dir`, matching RuleInfo.path as returned by list_rules()
    and list_attack_techniques().

    Raises HayabusaError if `path` doesn't end in .yml/.yaml, escapes `rules_dir`,
    or doesn't exist.
    """
    if not path.lower().endswith((".yml", ".yaml")):
        raise HayabusaError(f"Not a rule file (must end in .yml/.yaml): {path}")

    base = _resolve_rules_dir(rules_dir).resolve()
    candidate = (base / path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise HayabusaError(f"Rule path escapes the rules directory: {path}")

    if not candidate.is_file():
        raise HayabusaError(f"Rule file not found: {path}")

    return candidate.read_text(encoding="utf-8", errors="replace")


def _iter_json_documents(text: str) -> list:
    """Parse consecutive whitespace-separated JSON documents from `text`.

    hayabusa's json-timeline output (without -L) is neither a JSON array nor
    single-line JSONL: it's pretty-printed JSON objects concatenated back to
    back. This handles that, plus a JSON array, plus compact JSONL, with the
    same logic.
    """
    decoder = json.JSONDecoder()
    idx, n = 0, len(text)
    documents = []
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(text, idx)
        documents.append(obj)
        idx = end
    return documents


def _summarize(records: list[dict], top_n: int = 20) -> tuple[dict[str, int], list[dict]]:
    level_counts: dict[str, int] = {}
    rule_counts: dict[tuple[str, str], int] = {}
    for record in records:
        level = record.get("Level") or "unknown"
        level_counts[level] = level_counts.get(level, 0) + 1
        title = record.get("RuleTitle") or "unknown"
        key = (title, level)
        rule_counts[key] = rule_counts.get(key, 0) + 1

    top_rules = [
        {"rule_title": title, "level": level, "count": count}
        for (title, level), count in sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    ]
    return level_counts, top_rules


def _attach_preview(result: ScanResult, max_records: int = PREVIEW_RECORD_LIMIT) -> None:
    path = Path(result.output_path)

    if result.output_format == "csv":
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            rows = list(csv.DictReader(f))
        result.record_count = len(rows)
        result.level_counts, result.top_rules = _summarize(rows)
        result.preview = rows[:max_records]
        return

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if not text.strip():
        result.record_count = 0
        result.level_counts = {}
        result.top_rules = []
        result.preview = []
        return

    documents = _iter_json_documents(text)
    # A single JSON array document means the array elements are the records.
    records = documents[0] if len(documents) == 1 and isinstance(documents[0], list) else documents

    result.record_count = len(records)
    result.level_counts, result.top_rules = _summarize(records)
    result.preview = records[:max_records]
