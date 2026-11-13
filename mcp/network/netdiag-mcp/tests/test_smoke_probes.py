"""Every registered tool must carry a smoke-test probe spec.

This is the CI half of the smoke test: the live run (scripts/smoke_test.py)
needs real network access, but the *coverage* question -- did someone add a
tool without deciding how we would know it works? -- is answerable offline,
so it is enforced here on every push.

This intentionally does NOT carry the other family members' checks that
forbid address-shaped literals (IPs/hostnames/URLs) in smoke_probes.py. That
rule exists there to stop a public repo from leaking a private device
inventory. This server has no inventory at all -- every probe target is
deliberately a public, stable, non-identifying endpoint (1.1.1.1, example.com;
see smoke_probes.py's module docstring), so hardcoding them there is the
correct design, not something to forbid.
"""

import asyncio
import sys
from pathlib import Path

from netdiag_mcp.server import mcp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import smoke_probes  # noqa: E402 - needs the sys.path line above
from smoke_harness import Probe  # noqa: E402


def _registered_tool_names() -> set[str]:
    """Tool names from the live registry.

    ``asyncio.run`` rather than an async test: this suite has no async
    plugin, and the registry read is the only awaitable involved.
    """

    async def _names() -> set[str]:
        return {tool.name for tool in await mcp.list_tools()}

    return asyncio.run(_names())


def test_every_registered_tool_has_a_probe():
    registered = _registered_tool_names()
    missing = sorted(registered - set(smoke_probes.PROBES))
    assert not missing, (
        f"Tool(s) registered with no smoke-test probe: {missing}. "
        "Add an entry to scripts/smoke_probes.py -- arguments plus what a working "
        "answer looks like."
    )


def test_no_probe_targets_a_removed_tool():
    registered = _registered_tool_names()
    stale = sorted(set(smoke_probes.PROBES) - registered)
    assert not stale, f"Probe spec(s) for tools that are no longer registered: {stale}"


def test_probes_are_probe_instances():
    for name, probe in smoke_probes.PROBES.items():
        assert isinstance(probe, Probe), f"{name} is not a Probe"


def test_every_probe_asserts_something():
    """A probe that asserts nothing reports a broken tool as OK."""
    offenders = [
        name
        for name, probe in smoke_probes.PROBES.items()
        if not probe.must_match and not probe.min_chars and not probe.require_keys and not probe.min_values
    ]
    assert not offenders, (
        f"probes with nothing to assert: {offenders}. These tools answer with "
        "formatted text, so pin the shape they must produce (must_match) or at "
        "least a minimum length."
    )
