# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""``HOST-RESOURCES-MIB`` → ``host_resources`` tool (RFC 2790).

Surfaces CPU load per core, total/swap memory, and the storage table
(filesystems + RAM/swap reported uniformly through hrStorageTable).
"""

from __future__ import annotations

from typing import Any

from .. import oids
from ..errors import SnmpUnsupported
from ..session import HostSession
from ..transport import snmp_get, snmp_table, snmp_walk


async def host_resources(session: HostSession) -> dict[str, Any]:
    """Return CPU/mem/storage from HOST-RESOURCES-MIB.

    Raises ``SnmpUnsupported`` if the agent does not implement the MIB at
    all (no scalars, no tables responded).
    """
    scalars = await snmp_get(
        session,
        [
            oids.HR_SYSTEM_UPTIME,
            oids.HR_SYSTEM_DATE,
            oids.HR_SYSTEM_PROCESSES,
            oids.HR_SYSTEM_NUM_USERS,
            oids.HR_MEMORY_SIZE,
        ],
    )
    vb = scalars["varbinds"]

    hr_uptime = _int_or_none(vb.get(oids.HR_SYSTEM_UPTIME, {}).get("value"))
    hr_mem_kb = _int_or_none(vb.get(oids.HR_MEMORY_SIZE, {}).get("value"))

    # Treat the MIB as unsupported only when EVERY scalar came back as
    # noSuchInstance / noSuchObject (i.e., the agent doesn't register
    # HOST-RESOURCES-MIB at all). A partial response is acceptable.
    if all(v.get("value") is None for v in vb.values()):
        raise SnmpUnsupported(
            "agent does not implement HOST-RESOURCES-MIB",
            host=session.host_cfg.name,
        )

    # CPU load — walk hrProcessorLoad column (one row per logical CPU).
    cpu_walk = await snmp_walk(session, oids.HR_PROCESSOR_LOAD, use_bulk=True)
    cpu_load_pct = [_int_or_none(r["value"]) for r in cpu_walk["rows"]]

    # Storage table — covers RAM, swap, and filesystems.
    storage = await snmp_table(
        session,
        oids.HR_STORAGE_TABLE,
        column_names=oids.HR_STORAGE_TABLE_COLUMNS,
        use_bulk=True,
    )
    storage_out = []
    swap_kb: int | None = None
    real_kb: int | None = None
    for row in storage["rows"]:
        type_oid = _str_or_none(row.get("hrStorageType"))
        type_name = oids.HR_STORAGE_TYPE_NAMES.get(
            type_oid.lstrip(".") if type_oid else "",
            "unknown",
        )
        alloc = _int_or_none(row.get("hrStorageAllocationUnits"))
        size_units = _int_or_none(row.get("hrStorageSize"))
        used_units = _int_or_none(row.get("hrStorageUsed"))
        size_bytes = alloc * size_units if (alloc is not None and size_units is not None) else None
        used_bytes = alloc * used_units if (alloc is not None and used_units is not None) else None
        descr = _str_or_none(row.get("hrStorageDescr"))
        storage_out.append(
            {
                "index": row["index"],
                "descr": descr,
                "type": type_name,
                "type_oid": type_oid,
                "alloc_units_bytes": alloc,
                "size_units": size_units,
                "used_units": used_units,
                "size_bytes": size_bytes,
                "used_bytes": used_bytes,
            }
        )
        # Pluck swap and real-memory hints from the storage table so we can
        # report them even on agents that don't expose hrMemorySize.
        if type_name == "ram" and size_bytes is not None:
            real_kb = size_bytes // 1024
        elif type_name == "virtual_memory" and size_bytes is not None and real_kb is not None:
            # virtual_memory ≈ real + swap; subtract real (where known) for swap.
            candidate = (size_bytes // 1024) - real_kb
            if candidate > 0:
                swap_kb = candidate

    return {
        "data": {
            "hrSystemUptime_centiseconds": hr_uptime,
            "hrSystemUptime_seconds": (hr_uptime / 100.0) if hr_uptime is not None else None,
            "hrSystemDate": _str_or_none(vb.get(oids.HR_SYSTEM_DATE, {}).get("value")),
            "hrSystemProcesses": _int_or_none(vb.get(oids.HR_SYSTEM_PROCESSES, {}).get("value")),
            "hrSystemNumUsers": _int_or_none(vb.get(oids.HR_SYSTEM_NUM_USERS, {}).get("value")),
            "memory": {
                "physical_kb": hr_mem_kb,
                "real_kb": real_kb,
                "swap_kb": swap_kb,
            },
            "cpu_load_pct": cpu_load_pct,
            "storage": storage_out,
        },
        "warnings": list(scalars["warnings"])
        + list(cpu_walk["warnings"])
        + list(storage["warnings"]),
    }


def _int_or_none(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    return str(v)
