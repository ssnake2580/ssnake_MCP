from spoor_sift.cli import render_self_correction

# A transcript fragment in the exact shape scripts/real_case_run.py writes:
# "## <type> [<name>]" headers, "- tool_call → `name`" lines, ```-fenced content.
TRANSCRIPT = """# Real Case 001 run — transcript

## ai [timeline]
- tool_call → `log2timeline_run` args={"source": "citadeldc01.mem", "plaso_name": "case001.plaso"}
```
Building the super-timeline from the memory image, then slicing around the pivots.
```

## tool [log2timeline_run]
```
{"error": "allow-listed binary not found on PATH: 'log2timeline.py'", "tool_call_id": null, "hint": "Reason about the cause, adjust arguments, and retry — or use a related tool."}
```

## ai [timeline]
```
This is a tool availability constraint, not an evidence gap. The timeline is reconstructed analytically from the Volatility kernel timestamps already recovered.
```

## ai [ioc_correlation]
```
Proceeding to consolidate indicators.
```
"""


def test_render_self_correction_surfaces_failed_tool_error_and_recovery():
    out = render_self_correction(TRANSCRIPT)
    # the tool that failed, named
    assert "log2timeline_run" in out
    # the REAL error message, surfaced verbatim (not paraphrased)
    assert "not found on PATH" in out
    # the agent's own recovery reasoning, quoted faithfully
    assert "tool availability constraint, not an evidence gap" in out


def test_render_self_correction_reports_when_run_was_clean():
    # a transcript with no tool errors must not crash and must say so plainly
    clean = "## ai [triage]\n```\nAll tools succeeded; nothing to recover from.\n```\n"
    out = render_self_correction(clean)
    assert out.strip() != ""
    assert "no" in out.lower()  # e.g. "no tool failures recorded"


def test_recovery_survives_markdown_headers_and_skips_routing():
    # The recovery message can itself contain markdown '## ' headers (an inline
    # report) and be followed by a routing-only message. We must extract the real
    # reasoning, not be fooled into chopping the block or grabbing the routing line.
    transcript = (
        "## ai [timeline]\n- tool_call → `psort_query` args={}\n```\nQuerying the store.\n```\n\n"
        "## tool [psort_query]\n```\n"
        '{"error": "allow-listed binary not found on PATH: \'psort.py\'"}\n'
        "```\n\n"
        "## ai [timeline]\n```\n"
        "Both tools unavailable — reconstructed analytically from kernel timestamps.\n\n"
        "## EXECUTIVE SUMMARY\n\nDC01 is compromised.\n"
        "```\n\n"
        "## ai [timeline]\n```\nTransferring back to supervisor\n```\n"
    )
    out = render_self_correction(transcript)
    assert "reconstructed analytically from kernel timestamps" in out
    assert "Transferring back to supervisor" not in out


def test_recovery_does_not_borrow_a_different_agents_reasoning():
    # triage's tool fails and triage writes no per-failure reasoning (empty content,
    # just a routing call). The next substantive message belongs to a DIFFERENT
    # specialist and must NOT be misattributed as triage's recovery.
    transcript = (
        "## ai [triage]\n- tool_call → `tsk_fls` args={}\n```\nWalking the filesystem.\n```\n\n"
        "## tool [tsk_fls]\n```\n"
        '{"error": "allow-listed binary not found on PATH: \'fls\'"}\n'
        "```\n\n"
        "## ai [triage]\n- tool_call → `transfer_back_to_supervisor` args={}\n\n"
        "## ai [timeline]\n```\nBuilding the super-timeline from the memory image.\n```\n"
    )
    out = render_self_correction(transcript)
    assert "tsk_fls" in out  # the failure is still surfaced
    assert "Building the super-timeline" not in out  # timeline's words are not triage's recovery
