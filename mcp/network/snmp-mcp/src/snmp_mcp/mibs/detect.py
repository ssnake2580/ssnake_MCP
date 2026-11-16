# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""``device_detect`` — heuristic probe of which standard MIBs a device speaks.

Issues a small, fixed set of GETs (no walks, no tables) and reports which
of the IETF MIBs we care about answered. Useful as a smoke-test before
calling any of the heavier wrappers.
"""

from __future__ import annotations

from typing import Any

from .. import oids
from ..errors import SnmpNoSuchName
from ..session import HostSession
from ..transport import snmp_get


async def device_detect(session: HostSession) -> dict[str, Any]:
    """Probe sysObjectID + one OID per supported MIB; report what answered."""
    probe = [
        oids.SYS_OBJECT_ID,
        oids.SYS_DESCR,
        oids.IF_NUMBER,
        oids.HR_SYSTEM_UPTIME,
        oids.PRT_GENERAL_PRINTER_STATUS + ".1.1",
    ]
    if session.host_cfg.version == "v1":
        # SNMPv1's GET is all-or-nothing: if ANY OID in the request is
        # unimplemented, the agent returns noSuchName (errorStatus=2) for
        # the entire request. We pay N round-trips here to keep the probe
        # robust against minimally-conformant v1 agents (e.g. OKI C530dn,
        # which does not implement one of the supported probe OIDs).
        # ``device_detect`` is rarely called and the probe set is small,
        # so the latency cost is acceptable.
        result = await _probe_per_oid(session, probe)
    else:
        result = await snmp_get(session, probe)
    vb = result["varbinds"]

    sys_object_id = _str_or_none(vb.get(oids.SYS_OBJECT_ID, {}).get("value"))
    sys_descr = _str_or_none(vb.get(oids.SYS_DESCR, {}).get("value"))

    supported = []
    # SNMPv2-MIB is implied by any successful response to sysObjectID / sysDescr.
    if sys_object_id is not None or sys_descr is not None:
        supported.append("SNMPv2-MIB")
    if _is_present(vb.get(oids.IF_NUMBER, {})):
        supported.append("IF-MIB")
    if _is_present(vb.get(oids.HR_SYSTEM_UPTIME, {})):
        supported.append("HOST-RESOURCES-MIB")
    if _is_present(vb.get(oids.PRT_GENERAL_PRINTER_STATUS + ".1.1", {})):
        supported.append("PRINTER-MIB")

    vendor_hint = oids.vendor_from_sys_object_id(sys_object_id) if sys_object_id else "unknown"

    return {
        "data": {
            "sys_object_id": sys_object_id,
            "sys_descr": sys_descr,
            "vendor_hint": vendor_hint,
            "supported_mibs": supported,
        },
        "warnings": result["warnings"],
    }


async def _probe_per_oid(session: HostSession, probe: list[str]) -> dict[str, Any]:
    """Issue one GET per OID; absorb ``noSuchName`` as a synthetic absent varbind.

    SNMPv1 fails the whole request on any unimplemented OID. Catching the
    error per-OID lets ``device_detect`` report partial MIB support the
    same way it would for v2c+ noSuchObject markers.
    """
    out: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for oid in probe:
        try:
            sub = await snmp_get(session, [oid])
        except SnmpNoSuchName:
            out[oid] = {"value": None, "type": "noSuchInstance"}
            warnings.append(f"{oid}: noSuchName (v1)")
            continue
        out.update(sub["varbinds"])
        warnings.extend(sub["warnings"])
    return {"varbinds": out, "warnings": warnings}


def _is_present(vb_entry: dict[str, Any]) -> bool:
    """Return True if a varbind entry holds a real (non-sentinel) value."""
    if not vb_entry:
        return False
    if vb_entry.get("value") is None:
        return False
    type_name = vb_entry.get("type", "")
    return type_name not in ("noSuchInstance", "noSuchObject", "endOfMibView")


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    return str(v)
