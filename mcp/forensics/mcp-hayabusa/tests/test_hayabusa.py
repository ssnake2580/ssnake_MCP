from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa
from mcp_hayabusa.hayabusa import HayabusaError, list_rules, scan


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _install_fake_run(monkeypatch, records, *, calls=None, filter_dir_snapshot=None, returncode=0):
    """Monkeypatch subprocess.run so scan() never touches a real hayabusa binary.

    Writes `records` as a JSON array to whatever -o path is in the command
    (json_timeline's "single array" shape, which _iter_json_documents already
    supports). Records every invocation's command list into `calls` if given.

    scan() deletes the -r temp filter dir in a `finally` immediately after
    subprocess.run() returns — before the caller ever sees it — so if the
    filter dir's contents matter to a test, they must be snapshotted here,
    during the call, into `filter_dir_snapshot`.
    """

    def fake_run(command, capture_output, text, timeout):
        if calls is not None:
            calls.append(command)
        if filter_dir_snapshot is not None and "-r" in command:
            filter_dir = Path(command[command.index("-r") + 1])
            filter_dir_snapshot.extend(sorted(p.name for p in filter_dir.iterdir()))
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(json.dumps(records), encoding="utf-8")
        return FakeProc(returncode=returncode, stdout="ok", stderr="")

    monkeypatch.setattr(hayabusa.subprocess, "run", fake_run)


def _record(i, level="low", title="Rule"):
    return {"Timestamp": f"2024-01-01T00:00:{i:02d}Z", "RuleTitle": f"{title} {i}", "Level": level}


# --- rule_filter -----------------------------------------------------------


def test_rule_filter_restricts_to_matching_rules_by_raw_text(rules_dir, target_dir, fake_binary, monkeypatch):
    snapshot = []
    _install_fake_run(monkeypatch, [_record(0)], filter_dir_snapshot=snapshot)

    result = scan(target_dir, is_file=False, rule_filter="mimikatz", rules_dir=str(rules_dir))

    # "mimikatz" appears in creds/mimikatz.yml's title/description AND in
    # misc/malformed.yml's title (raw text match, independent of YAML validity).
    matched_names = sorted(name.split("_", 1)[1] for name in snapshot)
    assert matched_names == ["malformed.yml", "mimikatz.yml"]
    assert result.record_count == 1


def test_rule_filter_temp_dir_is_cleaned_up_after_scan(rules_dir, target_dir, fake_binary, monkeypatch):
    calls = []
    _install_fake_run(monkeypatch, [_record(0)], calls=calls)

    scan(target_dir, is_file=False, rule_filter="mimikatz", rules_dir=str(rules_dir))

    [command] = calls
    filter_dir = Path(command[command.index("-r") + 1])
    assert not filter_dir.exists()


def test_rule_filter_no_match_raises_without_running_hayabusa(rules_dir, target_dir, fake_binary, monkeypatch):
    calls = []
    _install_fake_run(monkeypatch, [], calls=calls)

    with pytest.raises(HayabusaError, match="No rules"):
        scan(target_dir, is_file=False, rule_filter="no-such-keyword-anywhere", rules_dir=str(rules_dir))

    assert calls == []


def test_rule_filter_bad_rules_dir_raises(target_dir, fake_binary, monkeypatch, tmp_path):
    _install_fake_run(monkeypatch, [])

    with pytest.raises(HayabusaError, match="rules_dir"):
        scan(target_dir, is_file=False, rule_filter="anything", rules_dir=str(tmp_path / "missing"))


# --- max_results -------------------------------------------------------------


def test_max_results_caps_preview_but_not_record_count(target_dir, fake_binary, monkeypatch):
    records = [_record(i, level="low" if i % 2 else "high") for i in range(25)]
    _install_fake_run(monkeypatch, records)

    result = scan(target_dir, is_file=False, max_results=5)

    assert result.record_count == 25
    assert len(result.preview) == 5
    # level_counts/top_rules are computed over all 25 records, not just the preview slice.
    assert sum(result.level_counts.values()) == 25


def test_default_preview_limit_applies_without_max_results(target_dir, fake_binary, monkeypatch):
    records = [_record(i) for i in range(25)]
    _install_fake_run(monkeypatch, records)

    result = scan(target_dir, is_file=False)

    assert result.record_count == 25
    assert len(result.preview) == hayabusa.PREVIEW_RECORD_LIMIT == 20


# --- output file disappearing after a successful run (Defender-quarantine style) ---


def test_output_file_read_failure_becomes_hayabusa_error(target_dir, fake_binary, monkeypatch):
    _install_fake_run(monkeypatch, [_record(0)])

    def raise_oserror(result, max_records):
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(hayabusa, "_attach_preview", raise_oserror)

    with pytest.raises(HayabusaError, match="could not be read afterward"):
        scan(target_dir, is_file=False)


# --- list_rules ----------------------------------------------------------------


def test_list_rules_no_keyword_returns_all_matched_but_only_valid_rules(rules_dir):
    rules, total_matched = list_rules(rules_dir=str(rules_dir))

    # All 5 .yml files match (no keyword filter), but only the 3 with a
    # `detection` block and valid YAML become RuleInfo entries.
    assert total_matched == 5
    assert {r.title for r in rules} == {
        "Suspicious Logon",
        "HackTool - Mimikatz Execution",
        "LSASS Memory Dump",
    }


def test_list_rules_keyword_matches_raw_text_but_only_parses_valid_yaml(rules_dir):
    rules, total_matched = list_rules(rules_dir=str(rules_dir), keyword="mimikatz")

    # mimikatz.yml (valid) and malformed.yml (invalid, but text-matches) both match...
    assert total_matched == 2
    # ...but only the valid one is returned as a parsed rule.
    assert len(rules) == 1
    assert rules[0].title == "HackTool - Mimikatz Execution"


def test_list_rules_keyword_matching_is_same_as_rule_filter(rules_dir, target_dir, fake_binary, monkeypatch):
    """The whole point of get_hayabusa_rules is that its keyword predicts rule_filter's set."""
    snapshot = []
    _install_fake_run(monkeypatch, [_record(0)], filter_dir_snapshot=snapshot)

    rules, total_matched = list_rules(rules_dir=str(rules_dir), keyword="mimikatz")
    scan(target_dir, is_file=False, rule_filter="mimikatz", rules_dir=str(rules_dir))

    assert total_matched == len(snapshot)


def test_list_rules_extracts_fields(rules_dir):
    rules, total_matched = list_rules(rules_dir=str(rules_dir), keyword="lateral")

    assert total_matched == 1
    [rule] = rules
    assert rule.id == "11111111-1111-1111-1111-111111111111"
    assert rule.title == "Suspicious Logon"
    assert rule.level == "low"
    assert rule.status == "stable"
    assert rule.author == "Test Author"
    assert rule.tags == ["attack.lateral-movement"]
    assert rule.logsource == {"product": "windows", "service": "security"}
    assert rule.path == "logon/suspicious_logon.yml"


def test_list_rules_max_results_caps_returned_but_not_total_matched(rules_dir):
    rules, total_matched = list_rules(rules_dir=str(rules_dir), max_results=1)

    assert total_matched == 5
    assert len(rules) == 1


def test_list_rules_no_keyword_match_returns_empty(rules_dir):
    rules, total_matched = list_rules(rules_dir=str(rules_dir), keyword="no-such-keyword-anywhere")

    assert rules == []
    assert total_matched == 0


def test_list_rules_bad_rules_dir_raises(tmp_path):
    with pytest.raises(HayabusaError, match="rules_dir"):
        list_rules(rules_dir=str(tmp_path / "missing"))


# --- list_attack_techniques / get_attack_technique_rules ------------------------


def test_list_attack_techniques_groups_by_technique_id(rules_dir):
    grouped = hayabusa.list_attack_techniques(rules_dir=str(rules_dir))

    # mimikatz.yml is tagged with both T1003.001 and T1003.002; lsass_dump.yml
    # only T1003.001. The bare parent T1003 is never tagged directly, so it's
    # absent. attack.credential-access (a tactic, not a technique) never appears.
    assert set(grouped) == {"T1003.001", "T1003.002"}
    assert {r.title for r in grouped["T1003.001"]} == {"HackTool - Mimikatz Execution", "LSASS Memory Dump"}
    assert [r.title for r in grouped["T1003.002"]] == ["HackTool - Mimikatz Execution"]


def test_list_attack_techniques_sorted_by_technique_id(rules_dir):
    grouped = hayabusa.list_attack_techniques(rules_dir=str(rules_dir))

    assert list(grouped) == sorted(grouped)


def test_get_attack_technique_rules_is_case_insensitive(rules_dir):
    rules = hayabusa.get_attack_technique_rules("t1003.001", rules_dir=str(rules_dir))

    assert {r.title for r in rules} == {"HackTool - Mimikatz Execution", "LSASS Memory Dump"}


def test_get_attack_technique_rules_no_match_returns_empty(rules_dir):
    assert hayabusa.get_attack_technique_rules("T9999", rules_dir=str(rules_dir)) == []


def test_list_attack_techniques_bad_rules_dir_raises(tmp_path):
    with pytest.raises(HayabusaError, match="rules_dir"):
        hayabusa.list_attack_techniques(rules_dir=str(tmp_path / "missing"))


# --- read_rule_file --------------------------------------------------------------


def test_read_rule_file_returns_raw_text(rules_dir):
    text = hayabusa.read_rule_file("creds/mimikatz.yml", rules_dir=str(rules_dir))

    assert "title: 'HackTool - Mimikatz Execution'" in text
    assert "detection:" in text


def test_read_rule_file_rejects_non_yaml_suffix(rules_dir):
    with pytest.raises(HayabusaError, match=r"\.yml/\.yaml"):
        hayabusa.read_rule_file("creds/mimikatz.exe", rules_dir=str(rules_dir))


def test_read_rule_file_rejects_path_traversal(rules_dir):
    with pytest.raises(HayabusaError, match="escapes"):
        hayabusa.read_rule_file("../../etc/passwd.yml", rules_dir=str(rules_dir))


def test_read_rule_file_missing_file_raises(rules_dir):
    with pytest.raises(HayabusaError, match="not found"):
        hayabusa.read_rule_file("creds/does_not_exist.yml", rules_dir=str(rules_dir))
