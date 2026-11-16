# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""``IF-MIB`` → ``interfaces_list`` tool (RFC 2863).

Walks both ``ifTable`` (.1.3.6.1.2.1.2.2) and ``ifXTable``
(.1.3.6.1.2.1.31.1.1) and merges per ``ifIndex``. HC counters
(``ifHCInOctets`` / ``ifHCOutOctets``) and ``ifHighSpeed`` from
``ifXTable`` are preferred where available — the 32-bit ``ifSpeed`` field
saturates at 4,294,967,295 bps (~4.29 Gbps), so 10G+ interfaces report
that value verbatim unless ``ifHighSpeed`` is consulted.
"""

from __future__ import annotations

from typing import Any

from .. import oids
from ..session import HostSession
from ..transport import snmp_table

_IF_SPEED_SATURATION = 4_294_967_295


async def interfaces_list(session: HostSession) -> dict[str, Any]:
    """Return per-interface state + counters, with HC + speed-saturation handling."""
    if_table = await snmp_table(
        session,
        oids.IF_TABLE,
        column_names=oids.IF_TABLE_COLUMNS,
        use_bulk=True,
    )
    if_x_table = await snmp_table(
        session,
        oids.IF_X_TABLE,
        column_names=oids.IF_X_TABLE_COLUMNS,
        use_bulk=True,
    )
    warnings: list[str] = list(if_table["warnings"]) + list(if_x_table["warnings"])

    x_by_index: dict[str, dict[str, Any]] = {row["index"]: row for row in if_x_table["rows"]}
    merged: list[dict[str, Any]] = []
    for row in if_table["rows"]:
        idx = row["index"]
        x_row = x_by_index.get(idx, {})
        if_speed = _int_or_none(row.get("ifSpeed"))
        if_high_speed = _int_or_none(x_row.get("ifHighSpeed"))
        speed_source = "ifSpeed"
        speed_bps: int | None = if_speed
        if if_speed is not None and if_speed >= _IF_SPEED_SATURATION and if_high_speed:
            speed_bps = if_high_speed * 1_000_000
            speed_source = "ifHighSpeed"
            warnings.append(
                f"ifIndex={idx}: ifSpeed saturated at 4.29 Gbps; "
                f"using ifHighSpeed={if_high_speed} Mbps"
            )
        elif if_speed is None and if_high_speed:
            speed_bps = if_high_speed * 1_000_000
            speed_source = "ifHighSpeed"
        elif if_speed is None and not if_high_speed:
            speed_source = "unknown"

        admin = _int_or_none(row.get("ifAdminStatus"))
        oper = _int_or_none(row.get("ifOperStatus"))

        merged.append(
            {
                "ifIndex": _int_or_none(row.get("ifIndex")) or _int_or_none(idx),
                "ifName": _str_or_none(x_row.get("ifName")) or _str_or_none(row.get("ifDescr")),
                "ifDescr": _str_or_none(row.get("ifDescr")),
                "ifAlias": _str_or_none(x_row.get("ifAlias")) or "",
                "ifType": _int_or_none(row.get("ifType")),
                "ifMtu": _int_or_none(row.get("ifMtu")),
                "ifAdminStatus": oids.IF_STATUS_NAMES.get(
                    admin, str(admin) if admin is not None else None
                ),
                "ifOperStatus": oids.IF_STATUS_NAMES.get(
                    oper, str(oper) if oper is not None else None
                ),
                "ifSpeed_bps": speed_bps,
                "ifSpeed_source": speed_source,
                "ifPhysAddress": _format_mac(row.get("ifPhysAddress")),
                "counters": {
                    "ifInOctets": _int_or_none(row.get("ifInOctets")),
                    "ifOutOctets": _int_or_none(row.get("ifOutOctets")),
                    "ifHCInOctets": _int_or_none(x_row.get("ifHCInOctets")),
                    "ifHCOutOctets": _int_or_none(x_row.get("ifHCOutOctets")),
                    "ifInErrors": _int_or_none(row.get("ifInErrors")),
                    "ifOutErrors": _int_or_none(row.get("ifOutErrors")),
                    "ifInDiscards": _int_or_none(row.get("ifInDiscards")),
                    "ifOutDiscards": _int_or_none(row.get("ifOutDiscards")),
                },
            }
        )

    return {"data": merged, "warnings": warnings}


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


def _format_mac(v: Any) -> str:
    """Format a MAC address out of the surrogate-escaped string pysnmp returns.

    OctetStrings in our pipeline are UTF-8/surrogate-escape decoded. For
    MAC-style OctetStrings the 6 raw bytes therefore come back as a
    surrogate-escape string; we re-encode to bytes and format as hex.
    """
    if v is None or v == "":
        return ""
    if isinstance(v, str):
        try:
            raw = v.encode("utf-8", errors="surrogateescape")
        except UnicodeError:
            return v
    elif isinstance(v, (bytes, bytearray)):
        raw = bytes(v)
    else:
        return str(v)
    if not raw:
        return ""
    return ":".join(f"{b:02x}" for b in raw)
