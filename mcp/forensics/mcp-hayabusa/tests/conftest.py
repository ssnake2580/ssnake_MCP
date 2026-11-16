"""Shared fixtures for the mcp_hayabusa test suite.

Tests never invoke the real hayabusa binary or need sample_evtx data — scan()
tests monkeypatch subprocess.run with a fake that writes synthetic output, and
list_rules() tests run against a small synthetic rules directory built here.
"""

from __future__ import annotations

import textwrap

import pytest

# Deliberately includes files that _rule_files_matching will find but
# list_rules() should skip: one with no `detection` block, one with invalid
# YAML (a tab character, which YAML forbids for indentation).
_LOGON_RULE = """
    title: Suspicious Logon
    id: 11111111-1111-1111-1111-111111111111
    level: low
    status: stable
    description: Detects suspicious logon activity, possible lateral movement.
    author: Test Author
    tags:
        - attack.lateral-movement
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4624
        condition: selection
    """

_MIMIKATZ_RULE = """
    title: 'HackTool - Mimikatz Execution'
    id: 22222222-2222-2222-2222-222222222222
    level: high
    status: stable
    description: Detects usage of the mimikatz credential dumping tool.
    author: Test Author
    tags:
        - attack.credential-access
        - attack.t1003.001
        - attack.t1003.002
    logsource:
        product: windows
        service: sysmon
    detection:
        selection:
            Image|endswith: mimikatz.exe
        condition: selection
    """

_LSASS_RULE = """
    title: LSASS Memory Dump
    id: 44444444-4444-4444-4444-444444444444
    level: critical
    status: stable
    description: Detects direct access to LSASS memory, another credential dumping technique.
    author: Test Author
    tags:
        - attack.credential-access
        - attack.t1003.001
    logsource:
        product: windows
        service: sysmon
    detection:
        selection:
            TargetImage|endswith: lsass.exe
        condition: selection
    """

_NO_DETECTION_RULE = """
    title: Not A Real Rule
    id: 33333333-3333-3333-3333-333333333333
    level: informational
    description: This file has no detection block and should be skipped.
    """

# Tab-indented block is invalid YAML (yaml.YAMLError) but the raw text still
# contains "mimikatz", so keyword matching (which is text-based) should still
# find it even though list_rules() can't parse it into a RuleInfo.
_MALFORMED_RULE = "title: Broken Rule mentions mimikatz\ndetection:\n\tselection: bad\n"

_RULES = {
    "logon/suspicious_logon.yml": textwrap.dedent(_LOGON_RULE).strip() + "\n",
    "creds/mimikatz.yml": textwrap.dedent(_MIMIKATZ_RULE).strip() + "\n",
    "creds/lsass_dump.yml": textwrap.dedent(_LSASS_RULE).strip() + "\n",
    "misc/no_detection.yml": textwrap.dedent(_NO_DETECTION_RULE).strip() + "\n",
    "misc/malformed.yml": _MALFORMED_RULE,
}


@pytest.fixture
def rules_dir(tmp_path):
    """A synthetic rules directory: 3 valid rules, 1 non-rule yml, 1 malformed yml.

    ATT&CK tags: mimikatz.yml -> T1003.001, T1003.002; lsass_dump.yml -> T1003.001.
    So T1003.001 has 2 rules, T1003.002 has 1, and T1003 (the parent, untagged
    directly) has none — exercises list_attack_techniques() grouping/multi-tag.
    """
    base = tmp_path / "rules"
    for rel_path, content in _RULES.items():
        path = base / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return base


@pytest.fixture
def fake_binary(monkeypatch):
    """Stand in for resolve_binary() so scan() tests don't need a real hayabusa install."""
    monkeypatch.setattr("mcp_hayabusa.hayabusa.resolve_binary", lambda: "fake-hayabusa")
    return "fake-hayabusa"


@pytest.fixture
def target_dir(tmp_path):
    """scan() requires the target path to exist; this stands in for a real .evtx directory."""
    target = tmp_path / "target"
    target.mkdir()
    return str(target)
