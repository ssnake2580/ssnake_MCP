"""FastMCP server exposing Hayabusa EVTX scanning as an MCP tool."""

from __future__ import annotations

from typing import Literal
from urllib.parse import unquote

from mcp.server.fastmcp import FastMCP

from mcp_hayabusa.hayabusa import (
    HayabusaError,
    RuleInfo,
    ScanResult,
    get_attack_technique_rules,
    list_attack_techniques,
    list_rules,
    read_rule_file,
    scan,
)

mcp = FastMCP("hayabusa")


_CONDENSED_FIELDS = ("Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID")


def _condense(record: dict) -> dict:
    return {field: record.get(field) for field in _CONDENSED_FIELDS if field in record}


@mcp.tool()
def scan_evtx(
    target: str,
    is_file: bool = False,
    output_format: Literal["csv", "json", "jsonl"] = "json",
    rules_dir: str | None = None,
    rule_filter: str | None = None,
    min_level: str | None = None,
    utc: bool = False,
    output_path: str | None = None,
    result_detail: Literal["summary", "full"] = "summary",
    max_results: int | None = None,
) -> dict:
    """Run a Hayabusa detection scan over Windows Event Log (.evtx) data.

    Wraps `hayabusa csv-timeline` / `hayabusa json-timeline`, always run
    non-interactively (no rule-config wizard, no launch banner).

    Args:
        target: Path to a single .evtx file (set is_file=True) or a
            directory containing .evtx files.
        is_file: True if `target` is a single .evtx file rather than a
            directory.
        output_format: "csv" (uses csv-timeline), or "json"/"jsonl"
            (both use json-timeline; jsonl adds Hayabusa's -L flag). This
            controls Hayabusa's own output format, not the shape of the
            dict returned by this tool — see result_detail for that.
        rules_dir: Optional path to a custom Sigma/Hayabusa rules
            directory or file (passed as -r). Defaults to Hayabusa's
            bundled ./rules. Ignored if rule_filter is set (see below).
        rule_filter: Only run rules whose rule file text contains this
            string (case-insensitive), e.g. "lateral" or "mimikatz".
            Hayabusa has no native free-text rule filter, so this copies
            matching rule files from rules_dir (or Hayabusa's default
            ./rules) into a temporary rules directory and scans with just
            those loaded.
        min_level: Optional minimum alert level to load: "informational",
            "low", "medium", "high", or "critical" (passed as -m).
        utc: Output timestamps in UTC instead of local time (-U).
        output_path: Where to write the full result file. If omitted, a
            temporary file is used and deleted after a preview is
            extracted, so the full result set is only kept on disk when
            you pass this explicitly.
        result_detail: "summary" (default) returns counts by level, the
            top matching rules, and a condensed preview (key fields only);
            stdout/stderr tails are only included on non-zero exit. "full"
            returns the complete record preview with all fields plus
            stdout/stderr tails, as before.
        max_results: Cap on the number of preview records returned
            (default 20). Does not affect record_count, which is always
            the true total.

    Returns:
        A dict shaped per result_detail; see above.
    """
    try:
        result: ScanResult = scan(
            target,
            is_file=is_file,
            output_format=output_format,
            rules_dir=rules_dir,
            rule_filter=rule_filter,
            min_level=min_level,
            utc=utc,
            output_path=output_path,
            max_results=max_results,
        )
    except HayabusaError as exc:
        return {"error": str(exc)}

    if result_detail == "full":
        return {
            "command": result.command,
            "returncode": result.returncode,
            "output_format": result.output_format,
            "output_path": output_path,
            "rule_filter": rule_filter,
            "record_count": result.record_count,
            "level_counts": result.level_counts,
            "top_rules": result.top_rules,
            "preview": result.preview,
            "stdout_tail": result.stdout_tail,
            "stderr_tail": result.stderr_tail,
        }

    summary: dict = {
        "returncode": result.returncode,
        "output_path": output_path,
        "rule_filter": rule_filter,
        "record_count": result.record_count,
        "level_counts": result.level_counts,
        "top_rules": result.top_rules,
        "preview": [_condense(r) for r in result.preview] if isinstance(result.preview, list) else result.preview,
    }
    if result.returncode != 0:
        summary["stdout_tail"] = result.stdout_tail
        summary["stderr_tail"] = result.stderr_tail
    return summary


def _rule_dict(rule: RuleInfo) -> dict:
    return {
        "path": rule.path,
        "id": rule.id,
        "title": rule.title,
        "level": rule.level,
        "status": rule.status,
        "description": rule.description,
        "author": rule.author,
        "tags": rule.tags,
        "logsource": rule.logsource,
    }


@mcp.tool()
def get_hayabusa_rules(
    keyword: str | None = None,
    rules_dir: str | None = None,
    max_results: int | None = None,
) -> dict:
    """List available Hayabusa/Sigma detection rules, optionally filtered by keyword.

    Useful for understanding what rules exist before running scan_evtx — e.g. call
    with keyword="mimikatz" to see which rules would be loaded by
    scan_evtx(rule_filter="mimikatz"), since both use the same case-insensitive
    match against rule file text.

    Args:
        keyword: Only return rules whose rule file text contains this string
            (case-insensitive), e.g. "lateral" or "mimikatz". Omit to list all
            rules (subject to max_results).
        rules_dir: Optional path to a custom Sigma/Hayabusa rules directory.
            Defaults to Hayabusa's bundled ./rules.
        max_results: Cap on the number of rules returned (default 50).
            total_matched in the response is always the true match count.

    Returns:
        A dict with total_matched (true count of matching rule files) and
        rules: a list of {path, id, title, level, status, description, author,
        tags, logsource}, capped at max_results. Each rule's `path` can be read
        in full (including its detection logic) via the hayabusa://rules/{path}
        resource — percent-encode any '/' in the path first.
    """
    try:
        rules, total_matched = list_rules(rules_dir=rules_dir, keyword=keyword, max_results=max_results)
    except HayabusaError as exc:
        return {"error": str(exc)}

    return {
        "keyword": keyword,
        "total_matched": total_matched,
        "returned": len(rules),
        "rules": [_rule_dict(r) for r in rules],
    }


@mcp.resource(
    "hayabusa://attack",
    name="attack-index",
    title="ATT&CK technique index",
    mime_type="application/json",
)
def attack_index_resource() -> dict:
    """Index of every ATT&CK technique ID present in the loaded Sigma rule set
    (parsed from rule tags like 'attack.t1003.001'), with a rule count for each.

    Drill into a specific technique's matching rules via
    hayabusa://attack/{technique_id}, e.g. hayabusa://attack/T1003.
    """
    grouped = list_attack_techniques()
    return {
        "total_techniques": len(grouped),
        "techniques": [{"technique_id": tid, "rule_count": len(rules)} for tid, rules in grouped.items()],
    }


@mcp.resource(
    "hayabusa://attack/{technique_id}",
    name="attack-technique",
    title="Rules for an ATT&CK technique",
    mime_type="application/json",
)
def attack_technique_resource(technique_id: str) -> dict:
    """Rules tagged with a specific ATT&CK technique ID, e.g. 'T1003' or
    'T1003.001' (case-insensitive). Answers "what rules do we have for T1003?".

    rule_count is 0 with an empty rules list if no loaded rule is tagged with
    this technique — not an error, just no matches.
    """
    rules = get_attack_technique_rules(technique_id)
    return {
        "technique_id": technique_id.strip().upper(),
        "rule_count": len(rules),
        "rules": [_rule_dict(r) for r in rules],
    }


@mcp.resource(
    "hayabusa://rules/{path}",
    name="rule-file",
    title="Raw Sigma rule YAML",
    mime_type="application/yaml",
)
def rule_resource(path: str) -> str:
    """Raw Sigma rule YAML (including its actual `detection:` logic) for a single
    rule file.

    `path` is the rule's `path` field as returned by get_hayabusa_rules or an
    ATT&CK resource, with each '/' percent-encoded as %2F — MCP resource URI
    templates only match a single path segment, so nested rule paths (the norm)
    need this encoding. This function percent-decodes it before resolving.
    """
    return read_rule_file(unquote(path))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
