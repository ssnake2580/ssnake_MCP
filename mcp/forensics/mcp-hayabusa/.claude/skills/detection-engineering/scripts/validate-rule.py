#!/usr/bin/env python3
"""Validate a Sigma rule YAML file against this repo's detection engineering standards
(see ../SKILL.md). Standalone script: only depends on PyYAML, not on the mcp_hayabusa
package, so it can run against any rule file regardless of where it lives.

Usage:
    python validate-rule.py <path-to-rule.yml>

Prints a JSON report to stdout and exits 0 if every check passes, 1 if any check
fails, or 2 if the file can't be read/parsed at all.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        json.dumps({"error": "PyYAML is required to run this script (pip install pyyaml)"}),
        file=sys.stderr,
    )
    sys.exit(2)

ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
ALLOWED_LEVELS = {"low", "medium", "high", "critical"}
TRIVIAL_FALSEPOSITIVES = {"unknown", "none", ""}
TEST_CASE_KEYWORD_RE = re.compile(r"\btest\b", re.IGNORECASE)
COMMENT_LINE_RE = re.compile(r"^\s*#(.*)$")


def check_attack_tags(data: dict) -> dict:
    tags = data.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]
    matched = [tag for tag in tags if isinstance(tag, str) and ATTACK_TAG_RE.match(tag.strip())]
    passed = bool(matched)
    detail = (
        f"Found ATT&CK technique tag(s): {matched}"
        if passed
        else "No tag matches attack.tXXXX or attack.tXXXX.XXX (e.g. attack.t1003.001)"
    )
    return {"passed": passed, "detail": detail, "tags_found": matched}


def check_severity_level(data: dict) -> dict:
    level = data.get("level")
    normalized = level.strip().lower() if isinstance(level, str) else None
    passed = normalized in ALLOWED_LEVELS
    detail = (
        f"level: {level!r} is valid"
        if passed
        else f"level: {level!r} is not one of {sorted(ALLOWED_LEVELS)}"
    )
    return {"passed": passed, "detail": detail, "level": level}


def check_falsepositives(data: dict) -> dict:
    falsepositives = data.get("falsepositives")
    if isinstance(falsepositives, str):
        falsepositives = [falsepositives]
    if not isinstance(falsepositives, list) or not falsepositives:
        return {"passed": False, "detail": "falsepositives is missing or empty"}

    substantive = [
        entry
        for entry in falsepositives
        if isinstance(entry, str) and entry.strip().lower() not in TRIVIAL_FALSEPOSITIVES
    ]
    passed = bool(substantive)
    detail = (
        f"falsepositives lists {len(substantive)} specific condition(s)"
        if passed
        else "falsepositives only contains trivial placeholders (e.g. 'Unknown'/'None') or is empty"
    )
    return {"passed": passed, "detail": detail}


def check_test_case_comment(data: dict, raw_text: str) -> dict:
    comment_hits = [
        match.group(1).strip()
        for line in raw_text.splitlines()
        if (match := COMMENT_LINE_RE.match(line)) and TEST_CASE_KEYWORD_RE.search(match.group(1))
    ]

    references = data.get("references") or []
    if isinstance(references, str):
        references = [references]
    reference_hits = [
        ref for ref in references if isinstance(ref, str) and TEST_CASE_KEYWORD_RE.search(ref)
    ]

    passed = bool(comment_hits or reference_hits)
    if passed:
        source = "comment" if comment_hits else "references"
        detail = f"Test case evidence found in {source}"
    else:
        detail = (
            "No test case evidence found — expected a '# ... test ...' comment or a "
            "references entry documenting what sample log/record the rule was validated against"
        )
    return {
        "passed": passed,
        "detail": detail,
        "comment_hits": comment_hits,
        "reference_hits": reference_hits,
    }


def validate(path: Path) -> dict:
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    data = yaml.safe_load(raw_text)
    if not isinstance(data, dict):
        return {
            "file": str(path),
            "valid": False,
            "error": "File does not parse to a YAML mapping (not a Sigma rule)",
        }

    checks = {
        "attack_tags": check_attack_tags(data),
        "severity_level": check_severity_level(data),
        "falsepositives": check_falsepositives(data),
        "test_case": check_test_case_comment(data, raw_text),
    }
    issues = [check["detail"] for check in checks.values() if not check["passed"]]

    return {
        "file": str(path),
        "valid": not issues,
        "checks": checks,
        "issues": issues,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: validate-rule.py <path-to-rule.yml>"}), file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        print(json.dumps({"error": f"File not found: {path}"}), file=sys.stderr)
        return 2

    try:
        report = validate(path)
    except yaml.YAMLError as exc:
        print(json.dumps({"error": f"Invalid YAML: {exc}"}), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2))
    if "error" in report:
        return 2
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
