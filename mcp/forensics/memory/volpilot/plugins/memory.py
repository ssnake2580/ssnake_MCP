"""Memory analysis plugin wrappers (vadinfo, vadwalk, ...)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from volatility3.framework import exceptions
from volatility3.plugins.windows import memmap, shimcachemem, strings, vadinfo, vadregexscan, vadwalk, virtmap

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session

# vadyarascan imports volatility3.plugins.yarascan, which re-raises
# ImportError at module load if neither yara-x nor yara-python (>=3.8) is
# installed. Guard it so the rest of the memory tools stay available on a
# minimal install.
try:
    from volatility3.plugins.windows import vadyarascan

    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False


def run_vadinfo(session: Session) -> dict:
    """Run windows.vadinfo and return VAD (Virtual Address Descriptor) details."""
    treegrid = run_plugin(session, vadinfo.VadInfo)
    return {"plugin": "vadinfo", "results": parse_treegrid(treegrid)}


def run_vadwalk(session: Session) -> dict:
    """Run windows.vadwalk and return VAD tree structure."""
    treegrid = run_plugin(session, vadwalk.VadWalk)
    return {"plugin": "vadwalk", "results": parse_treegrid(treegrid)}


def run_memmap(session: Session) -> dict:
    """Run windows.memmap and return virtual-to-physical memory mappings."""
    treegrid = run_plugin(session, memmap.Memmap)
    return {"plugin": "memmap", "results": parse_treegrid(treegrid)}


def run_virtmap(session: Session) -> dict:
    """Run windows.virtmap and return virtual mapped sections.

    Some Windows builds' kernel PDB lacks both symbols volatility3 knows
    how to read the system VA layout from (MiVisibleState,
    MiSystemVaType); the plugin raises SymbolError uncaught in that case
    instead of returning empty like similarly version-gated plugins
    (e.g. svclist). Caught here and translated into an empty result.
    """
    try:
        treegrid = run_plugin(session, virtmap.VirtMap)
    except exceptions.SymbolError:
        return {"plugin": "virtmap", "results": []}
    return {"plugin": "virtmap", "results": parse_treegrid(treegrid)}


def run_strings(session: Session, strings_file: str = "") -> dict:
    """Run windows.strings and return strings mapped to processes.

    strings_file: absolute path to a pre-generated strings-with-offsets
        file, e.g. produced by `strings -a -t d <image> > strings.txt`.
        This is a hard (non-optional) requirement of the underlying
        plugin -- without it, plugin construction itself fails
        validation before run() is ever reached, so an empty string
        here returns an empty result with an explanatory error instead
        of letting that exception propagate.
    """
    if not strings_file:
        return {
            "plugin": "strings",
            "results": [],
            "error": (
                "strings_file is required by windows.strings and was not "
                "provided. Generate one first (e.g. `strings -a -t d "
                "<image> > strings.txt` on Linux/WSL, or any tool that "
                "emits 'offset:string' lines) and pass its absolute path."
            ),
        }
    extra_config = {"strings_file": Path(strings_file).resolve().as_uri()}
    try:
        treegrid = run_plugin(session, strings.Strings, extra_config=extra_config)
    except exceptions.PluginRequirementException as e:
        return {"plugin": "strings", "results": [], "error": str(e)}
    return {"plugin": "strings", "results": parse_treegrid(treegrid)}


def run_shimcachemem(session: Session) -> dict:
    """Run windows.shimcachemem and return Application Compatibility Cache entries."""
    treegrid = run_plugin(session, shimcachemem.ShimcacheMem)
    return {"plugin": "shimcachemem", "results": parse_treegrid(treegrid)}


def run_vadregexscan(session: Session, pattern: str, maxsize: int = 128) -> dict:
    """Run windows.vadregexscan against every process VAD with the given regex.

    pattern: regex pattern to search (required by the plugin).
    maxsize: maximum byte context around each match (default 128).
    """
    treegrid = run_plugin(
        session,
        vadregexscan.VadRegExScan,
        extra_config={"pattern": pattern, "maxsize": maxsize},
    )
    return {"plugin": "vadregexscan", "results": parse_treegrid(treegrid)}


if _HAS_YARA:

    def run_vadyarascan(session: Session, yara_rule: str, pid: int = 0) -> dict:
        """Run windows.vadyarascan to scan every process VAD with a Yara rule.

        yara_rule: inline Yara rule text or bare string/hex pattern (required;
            passed through as the plugin's `yara_string` option).
        pid: optional filter to a single process ID (0 = scan all processes).

        Requires the optional `yara-python` (or `yara-x`) dependency.
        """
        extra: dict = {"yara_string": yara_rule}
        if pid:
            extra["pid"] = [pid]
        treegrid = run_plugin(session, vadyarascan.VadYaraScan, extra_config=extra)
        return {"plugin": "vadyarascan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "memmap": run_memmap,
    "shimcachemem": run_shimcachemem,
    "strings": run_strings,
    "vadinfo": run_vadinfo,
    "vadregexscan": run_vadregexscan,
    "vadwalk": run_vadwalk,
    "virtmap": run_virtmap,
}

if _HAS_YARA:
    PLUGIN_MAP["vadyarascan"] = run_vadyarascan
