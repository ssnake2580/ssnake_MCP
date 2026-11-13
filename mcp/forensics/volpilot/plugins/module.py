"""Module / DLL analysis plugin wrappers (dlllist, ldrmodules, modules, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import dlllist, iat, modscan, modules, pe_symbols, pedump, verinfo

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_dlllist(session: Session) -> dict:
    """Run windows.dlllist and return loaded modules per process."""
    treegrid = run_plugin(session, dlllist.DllList)
    return {"plugin": "dlllist", "results": parse_treegrid(treegrid)}


def run_modules(session: Session) -> dict:
    """Run windows.modules and return loaded kernel modules."""
    treegrid = run_plugin(session, modules.Modules)
    return {"plugin": "modules", "results": parse_treegrid(treegrid)}


def run_modscan(session: Session) -> dict:
    """Run windows.modscan and return kernel modules found by pool scanning."""
    treegrid = run_plugin(session, modscan.ModScan)
    return {"plugin": "modscan", "results": parse_treegrid(treegrid)}


def run_verinfo(session: Session) -> dict:
    """Run windows.verinfo and return PE version information."""
    treegrid = run_plugin(session, verinfo.VerInfo)
    return {"plugin": "verinfo", "results": parse_treegrid(treegrid)}


def run_iat(session: Session) -> dict:
    """Run windows.iat and return Import Address Table entries."""
    treegrid = run_plugin(session, iat.IAT)
    return {"plugin": "iat", "results": parse_treegrid(treegrid)}


def run_pe_symbols(
    session: Session,
    source: str,
    module: str,
    symbols: str = "",
    addresses: str = "",
) -> dict:
    """Run windows.pe_symbols to resolve PE symbol names <-> addresses.

    source: "kernel" or "processes".
    module: target module name (e.g., "ntoskrnl.exe", "ntdll.dll").
    symbols: optional comma-separated symbol names to resolve (name -> address).
    addresses: optional comma-separated hex/decimal addresses (address -> name).
    One of the two is effectively required: if both are empty the plugin
    logs an error and returns zero rows rather than listing every symbol.
    """
    extra: dict = {"source": source, "module": module}
    sym_list = [s.strip() for s in symbols.split(",") if s.strip()] if symbols else None
    if sym_list:
        extra["symbols"] = sym_list
    addr_list = [int(a.strip(), 0) for a in addresses.split(",") if a.strip()] if addresses else None
    if addr_list:
        extra["addresses"] = addr_list
    treegrid = run_plugin(session, pe_symbols.PESymbols, extra_config=extra)
    return {"plugin": "pe_symbols", "results": parse_treegrid(treegrid)}


def run_pedump(
    session: Session,
    base: int,
    pid: int = 0,
    kernel_module: bool = False,
) -> dict:
    """Run windows.pedump to dump a PE image at ``base`` into VOL_DUMP_DIR.

    base: required virtual base address of the PE (int).
    pid: optional process ID scope. When 0 and kernel_module is False, the
        plugin searches every userland process for the given base.
    kernel_module: set True to dump a kernel-mode PE (driver) instead of a
        userland module.
    """
    extra: dict = {"base": base}
    if pid:
        extra["pid"] = [pid]
    if kernel_module:
        extra["kernel_module"] = True
    treegrid = run_plugin(
        session,
        pedump.PEDump,
        extra_config=extra,
        open_method=session.file_handler,
    )
    return {"plugin": "pedump", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "dlllist": run_dlllist,
    "iat": run_iat,
    "modscan": run_modscan,
    "modules": run_modules,
    "pe_symbols": run_pe_symbols,
    "pedump": run_pedump,
    "verinfo": run_verinfo,
}
