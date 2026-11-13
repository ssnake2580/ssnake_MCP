"""Kernel / driver analysis plugin wrappers (bigpools, callbacks, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import bigpools, callbacks, debugregisters, devicetree, driverirp, driverscan, etwpatch, kpcrs, poolscanner, ssdt, timers, unloadedmodules

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_bigpools(session: Session) -> dict:
    """Run windows.bigpools and return big page pool allocations."""
    treegrid = run_plugin(session, bigpools.BigPools)
    return {"plugin": "bigpools", "results": parse_treegrid(treegrid)}


def run_callbacks(session: Session) -> dict:
    """Run windows.callbacks and return kernel callbacks and notification routines."""
    treegrid = run_plugin(session, callbacks.Callbacks)
    return {"plugin": "callbacks", "results": parse_treegrid(treegrid)}


def run_devicetree(session: Session) -> dict:
    """Run windows.devicetree and return device tree by drivers."""
    treegrid = run_plugin(session, devicetree.DeviceTree)
    return {"plugin": "devicetree", "results": parse_treegrid(treegrid)}


def run_driverirp(session: Session) -> dict:
    """Run windows.driverirp and return IRP handler table for drivers."""
    treegrid = run_plugin(session, driverirp.DriverIrp)
    return {"plugin": "driverirp", "results": parse_treegrid(treegrid)}


def run_ssdt(session: Session) -> dict:
    """Run windows.ssdt and return System Service Descriptor Table entries."""
    treegrid = run_plugin(session, ssdt.SSDT)
    return {"plugin": "ssdt", "results": parse_treegrid(treegrid)}


def run_poolscanner(session: Session) -> dict:
    """Run windows.poolscanner and return generic pool scan results."""
    treegrid = run_plugin(session, poolscanner.PoolScanner)
    return {"plugin": "poolscanner", "results": parse_treegrid(treegrid)}


def run_driverscan(session: Session) -> dict:
    """Run windows.driverscan and return driver objects found by pool scanning."""
    treegrid = run_plugin(session, driverscan.DriverScan)
    return {"plugin": "driverscan", "results": parse_treegrid(treegrid)}


def run_kpcrs(session: Session) -> dict:
    """Run windows.kpcrs and return per-CPU KPCR / PRCB offsets."""
    treegrid = run_plugin(session, kpcrs.KPCRs)
    return {"plugin": "kpcrs", "results": parse_treegrid(treegrid)}


def run_unloadedmodules(session: Session) -> dict:
    """Run windows.unloadedmodules and return recently unloaded kernel modules."""
    treegrid = run_plugin(session, unloadedmodules.UnloadedModules)
    return {"plugin": "unloadedmodules", "results": parse_treegrid(treegrid)}


def run_timers(session: Session) -> dict:
    """Run windows.timers and return registered kernel DPC timers."""
    treegrid = run_plugin(session, timers.Timers)
    return {"plugin": "timers", "results": parse_treegrid(treegrid)}


def run_debugregisters(session: Session) -> dict:
    """Run windows.debugregisters and return per-thread DR0-DR3 / DR7 state."""
    treegrid = run_plugin(session, debugregisters.DebugRegisters)
    return {"plugin": "debugregisters", "results": parse_treegrid(treegrid)}


def run_etwpatch(session: Session, pid: int = 0) -> dict:
    """Run windows.etwpatch and return ETW-tampered ntdll stubs.

    pid: optional process ID filter. 0 (default) scans every userland process.
    """
    extra: dict = {}
    if pid:
        extra["pid"] = [pid]
    treegrid = run_plugin(
        session,
        etwpatch.EtwPatch,
        extra_config=extra or None,
    )
    return {"plugin": "etwpatch", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "bigpools": run_bigpools,
    "callbacks": run_callbacks,
    "debugregisters": run_debugregisters,
    "devicetree": run_devicetree,
    "driverirp": run_driverirp,
    "driverscan": run_driverscan,
    "etwpatch": run_etwpatch,
    "kpcrs": run_kpcrs,
    "poolscanner": run_poolscanner,
    "ssdt": run_ssdt,
    "timers": run_timers,
    "unloadedmodules": run_unloadedmodules,
}
