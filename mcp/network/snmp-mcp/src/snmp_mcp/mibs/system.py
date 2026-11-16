# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""``SNMPv2-MIB::system`` group → ``system_info`` tool (RFC 3418)."""

from __future__ import annotations

from typing import Any

from .. import oids
from ..session import HostSession
from ..transport import snmp_get


async def system_info(session: HostSession) -> dict[str, Any]:
    """Fetch the SNMPv2-MIB::system scalar group in one GET-Request."""
    req = [
        oids.SYS_DESCR,
        oids.SYS_OBJECT_ID,
        oids.SYS_UP_TIME,
        oids.SYS_CONTACT,
        oids.SYS_NAME,
        oids.SYS_LOCATION,
        oids.SYS_SERVICES,
    ]
    result = await snmp_get(session, req)
    vb = result["varbinds"]
    sys_up_ticks = _int_or_none(vb.get(oids.SYS_UP_TIME, {}).get("value"))
    sys_services = _int_or_none(vb.get(oids.SYS_SERVICES, {}).get("value"))
    return {
        "data": {
            "sysDescr": _str_or_none(vb.get(oids.SYS_DESCR, {}).get("value")),
            "sysObjectID": _str_or_none(vb.get(oids.SYS_OBJECT_ID, {}).get("value")),
            "sysUpTime": sys_up_ticks,
            "sysUpTime_seconds": (sys_up_ticks / 100.0) if sys_up_ticks is not None else None,
            "sysContact": _str_or_none(vb.get(oids.SYS_CONTACT, {}).get("value")),
            "sysName": _str_or_none(vb.get(oids.SYS_NAME, {}).get("value")),
            "sysLocation": _str_or_none(vb.get(oids.SYS_LOCATION, {}).get("value")),
            "sysServices": sys_services,
        },
        "warnings": result["warnings"],
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
