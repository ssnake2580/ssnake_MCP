"""Tests for the detection-engineering skill's validate-rule.py script.

The script lives under .claude/skills/ as a standalone CLI (not part of the
mcp_hayabusa package), so it's loaded here via importlib from its file path and
exercised both at the function level and as a subprocess, to also cover its
JSON-output/exit-code CLI contract. Never touches the real hayabusa binary or
sample_evtx data.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent
    / ".claude"
    / "skills"
    / "detection-engineering"
    / "scripts"
    / "validate-rule.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_rule", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validate_rule = _load_module()


_VALID_RULE = """
    title: LSASS Memory Dump via Comsvcs
    id: 11111111-1111-1111-1111-111111111111
    status: experimental
    description: |
        level: high - direct evidence of credential dumping via LSASS access, low benign rate.
    references:
        - https://attack.mitre.org/techniques/T1003/001/
        - |
          Test evidence: validated against sample_evtx/Credential Access/sysmon_10_1_memdump.evtx,
          expected match: high.
    author: Test Author
    tags:
        - attack.credential-access
        - attack.t1003.001
    logsource:
        category: process_access
        product: windows
    detection:
        selection:
            TargetImage|endswith: lsass.exe
        condition: selection
    falsepositives:
        - Endpoint agents that walk lsass.exe memory for legitimate scanning purposes
    level: high
    """

_INVALID_RULE = """
    title: Bad Rule
    id: 22222222-2222-2222-2222-222222222222
    status: experimental
    description: A rule with no justification.
    tags:
        - attack.credential-access
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            Image|endswith: evil.exe
        condition: selection
    falsepositives:
        - Unknown
    level: informational
    """


def _write_rule(tmp_path, text, name="rule.yml"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")
    return path


# --- individual checks -------------------------------------------------------


def test_check_attack_tags_passes_on_valid_tag():
    result = validate_rule.check_attack_tags({"tags": ["attack.credential-access", "attack.t1003.001"]})
    assert result["passed"] is True
    assert result["tags_found"] == ["attack.t1003.001"]


def test_check_attack_tags_fails_with_no_technique_tag():
    result = validate_rule.check_attack_tags({"tags": ["attack.credential-access"]})
    assert result["passed"] is False


def test_check_severity_level_rejects_informational():
    assert validate_rule.check_severity_level({"level": "informational"})["passed"] is False


@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
def test_check_severity_level_accepts_allowed_values(level):
    assert validate_rule.check_severity_level({"level": level})["passed"] is True


def test_check_falsepositives_rejects_unknown_only():
    assert validate_rule.check_falsepositives({"falsepositives": ["Unknown"]})["passed"] is False


def test_check_falsepositives_rejects_missing_or_empty():
    assert validate_rule.check_falsepositives({})["passed"] is False
    assert validate_rule.check_falsepositives({"falsepositives": []})["passed"] is False


def test_check_falsepositives_accepts_specific_condition():
    result = validate_rule.check_falsepositives(
        {"falsepositives": ["Administrative use of PsExec for patch deployment"]}
    )
    assert result["passed"] is True


def test_check_test_case_comment_finds_reference_mention():
    result = validate_rule.check_test_case_comment(
        {"references": ["Test evidence: validated against sample.evtx"]}, raw_text=""
    )
    assert result["passed"] is True
    assert result["reference_hits"]


def test_check_test_case_comment_finds_yaml_comment():
    raw_text = "# Test case: validated against sample.evtx\ntitle: x\n"
    result = validate_rule.check_test_case_comment({}, raw_text=raw_text)
    assert result["passed"] is True
    assert result["comment_hits"]


def test_check_test_case_comment_fails_with_no_evidence():
    result = validate_rule.check_test_case_comment(
        {"references": ["https://attack.mitre.org"]}, raw_text="title: x\n"
    )
    assert result["passed"] is False


# --- validate() end to end ----------------------------------------------------


def test_validate_passes_a_fully_compliant_rule(tmp_path):
    path = _write_rule(tmp_path, _VALID_RULE)
    report = validate_rule.validate(path)
    assert report["valid"] is True
    assert report["issues"] == []


def test_validate_flags_every_failing_check(tmp_path):
    path = _write_rule(tmp_path, _INVALID_RULE)
    report = validate_rule.validate(path)
    assert report["valid"] is False
    failed_checks = {name for name, check in report["checks"].items() if not check["passed"]}
    assert failed_checks == {"attack_tags", "severity_level", "falsepositives", "test_case"}


def test_validate_rejects_non_mapping_yaml(tmp_path):
    path = _write_rule(tmp_path, "- just\n- a\n- list\n")
    report = validate_rule.validate(path)
    assert report["valid"] is False
    assert "error" in report


# --- CLI subprocess contract ---------------------------------------------------


def test_cli_exits_zero_on_valid_rule(tmp_path):
    path = _write_rule(tmp_path, _VALID_RULE)
    proc = subprocess.run([sys.executable, str(_SCRIPT_PATH), str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["valid"] is True


def test_cli_exits_one_on_invalid_rule(tmp_path):
    path = _write_rule(tmp_path, _INVALID_RULE)
    proc = subprocess.run([sys.executable, str(_SCRIPT_PATH), str(path)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["valid"] is False


def test_cli_exits_two_on_missing_file(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT_PATH), str(tmp_path / "missing.yml")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "error" in json.loads(proc.stderr)
