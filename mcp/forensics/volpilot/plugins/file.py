"""File analysis plugin wrappers (filescan, dumpfiles, symlinkscan, mutantscan)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import dumpfiles, filescan, mutantscan, symlinkscan

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session

# mftscan imports volatility3.plugins.yarascan (it reuses the Yara scanner
# internally, with a hardcoded rule, to locate $MFT record signatures), which
# re-raises ImportError at module load if neither yara-x nor yara-python
# (>=3.8) is installed. Guard it so the rest of the file tools stay available
# on a minimal install.
try:
    from volatility3.plugins.windows import mftscan

    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False


def run_filescan(session: Session) -> dict:
    """Run windows.filescan and return file objects found by pool scanning."""
    treegrid = run_plugin(session, filescan.FileScan)
    return {"plugin": "filescan", "results": parse_treegrid(treegrid)}


def run_dumpfiles(
    session: Session,
    pid: int = 0,
    filter: str = "",
    filter_ignore_case: bool = False,
    virtaddr: int = 0,
    physaddr: int = 0,
) -> dict:
    """Run windows.dumpfiles and write cached file contents to VOL_DUMP_DIR.

    Parameters mirror the volatility3 CLI flags (all optional):
      pid               --pid                filter to one process
      filter            --filter             regex filter on filename
      filter_ignore_case --ignore-case       case-insensitive filter
      virtaddr          --virtaddr           specific virtual address
      physaddr          --physaddr           specific physical address

    Passing ``0`` / ``""`` means the flag is left unset. Dumped bytes land
    in ``VOL_DUMP_DIR`` via ``session.file_handler``; the returned
    ``Result`` column contains the final on-disk path.
    """
    extra: dict = {}
    if pid:
        extra["pid"] = pid
    if filter:
        extra["filter"] = filter
    if filter_ignore_case:
        extra["ignore-case"] = True
    if virtaddr:
        extra["virtaddr"] = [virtaddr]
    if physaddr:
        extra["physaddr"] = [physaddr]

    treegrid = run_plugin(
        session,
        dumpfiles.DumpFiles,
        extra_config=extra or None,
        open_method=session.file_handler,
    )
    return {"plugin": "dumpfiles", "results": parse_treegrid(treegrid)}


def run_symlinkscan(session: Session) -> dict:
    """Run windows.symlinkscan and return symbolic link objects."""
    treegrid = run_plugin(session, symlinkscan.SymlinkScan)
    return {"plugin": "symlinkscan", "results": parse_treegrid(treegrid)}


def run_mutantscan(session: Session) -> dict:
    """Run windows.mutantscan and return mutex objects found by pool scanning."""
    treegrid = run_plugin(session, mutantscan.MutantScan)
    return {"plugin": "mutantscan", "results": parse_treegrid(treegrid)}


if _HAS_YARA:

    def run_mftscan(session: Session) -> dict:
        """Run windows.mftscan and return parsed $MFT FILE records found by signature scanning.

        Locates raw MFT records directly in memory (independent of a mounted
        filesystem), useful for recovering deleted/unlinked file metadata.

        Requires the optional `yara-python` (or `yara-x`) dependency (the
        plugin reuses the Yara scanner internally with a fixed signature).
        """
        treegrid = run_plugin(session, mftscan.MFTScan)
        return {"plugin": "mftscan", "results": parse_treegrid(treegrid)}

    def run_mftscan_ads(session: Session) -> dict:
        """Run windows.mftscan.ADS and return Alternate Data Stream records.

        Uses the same raw MFT signature scan as run_mftscan to locate
        $DATA attributes with a non-empty stream name attached to each MFT
        record, independent of a mounted filesystem.

        Requires the optional `yara-python` (or `yara-x`) dependency, same
        as run_mftscan.
        """
        treegrid = run_plugin(session, mftscan.ADS)
        return {"plugin": "mftscan.ads", "results": parse_treegrid(treegrid)}

    def run_mftscan_residentdata(session: Session) -> dict:
        """Run windows.mftscan.ResidentData and return resident $DATA content.

        Uses the same raw MFT signature scan as run_mftscan to recover
        file content stored inline in the MFT record itself (NTFS does
        this for files small enough to fit), independent of a mounted
        filesystem.

        Requires the optional `yara-python` (or `yara-x`) dependency, same
        as run_mftscan.
        """
        treegrid = run_plugin(session, mftscan.ResidentData)
        return {
            "plugin": "mftscan.residentdata",
            "results": parse_treegrid(treegrid),
        }


PLUGIN_MAP = {
    "dumpfiles": run_dumpfiles,
    "filescan": run_filescan,
    "mutantscan": run_mutantscan,
    "symlinkscan": run_symlinkscan,
}

if _HAS_YARA:
    PLUGIN_MAP["mftscan"] = run_mftscan
    PLUGIN_MAP["mftscan.ads"] = run_mftscan_ads
    PLUGIN_MAP["mftscan.residentdata"] = run_mftscan_residentdata
