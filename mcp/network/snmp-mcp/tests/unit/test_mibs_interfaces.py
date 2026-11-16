# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for mibs/interfaces.py — IF-MIB walk + HC-counter + saturation."""

from __future__ import annotations

from snmp_mcp import transport
from snmp_mcp.mibs.interfaces import _IF_SPEED_SATURATION, interfaces_list


def _mac_surrogate(b: bytes) -> str:
    """Return the surrogate-escape decoded form a pysnmp OctetString would land at."""
    return b.decode("utf-8", errors="surrogateescape")


async def test_interfaces_list_two_interfaces(monkeypatch, fake_session) -> None:
    # ifTable .1.3.6.1.2.1.2.2 rows for ifIndex 1, 2
    if_table_rows = [
        # ifIndex
        ("1.3.6.1.2.1.2.2.1.1.1", 1, "Integer"),
        ("1.3.6.1.2.1.2.2.1.1.2", 2, "Integer"),
        # ifDescr
        ("1.3.6.1.2.1.2.2.1.2.1", "lo", "OctetString"),
        ("1.3.6.1.2.1.2.2.1.2.2", "ether1", "OctetString"),
        # ifType
        ("1.3.6.1.2.1.2.2.1.3.1", 24, "Integer"),
        ("1.3.6.1.2.1.2.2.1.3.2", 6, "Integer"),
        # ifMtu
        ("1.3.6.1.2.1.2.2.1.4.1", 65536, "Integer"),
        ("1.3.6.1.2.1.2.2.1.4.2", 1500, "Integer"),
        # ifSpeed — interface 2 is saturated at 4.29 Gbps (a real 10G link)
        ("1.3.6.1.2.1.2.2.1.5.1", 10000000, "Gauge32"),
        ("1.3.6.1.2.1.2.2.1.5.2", _IF_SPEED_SATURATION, "Gauge32"),
        # ifPhysAddress (empty for lo; 6-byte MAC for ether1)
        ("1.3.6.1.2.1.2.2.1.6.1", "", "OctetString"),
        (
            "1.3.6.1.2.1.2.2.1.6.2",
            _mac_surrogate(bytes([0x90, 0x09, 0xD0, 0x89, 0x56, 0xC4])),
            "OctetString",
        ),
        # ifAdminStatus + ifOperStatus
        ("1.3.6.1.2.1.2.2.1.7.1", 1, "Integer"),
        ("1.3.6.1.2.1.2.2.1.7.2", 1, "Integer"),
        ("1.3.6.1.2.1.2.2.1.8.1", 1, "Integer"),
        ("1.3.6.1.2.1.2.2.1.8.2", 1, "Integer"),
        # ifInOctets / ifOutOctets (32-bit)
        ("1.3.6.1.2.1.2.2.1.10.1", 1000, "Counter32"),
        ("1.3.6.1.2.1.2.2.1.10.2", 4_000_000_000, "Counter32"),
        ("1.3.6.1.2.1.2.2.1.16.1", 2000, "Counter32"),
        ("1.3.6.1.2.1.2.2.1.16.2", 3_500_000_000, "Counter32"),
    ]
    if_x_table_rows = [
        # ifName
        ("1.3.6.1.2.1.31.1.1.1.1.1", "lo", "OctetString"),
        ("1.3.6.1.2.1.31.1.1.1.1.2", "ether1", "OctetString"),
        # ifHCInOctets / ifHCOutOctets (64-bit)
        ("1.3.6.1.2.1.31.1.1.1.6.1", 1000, "Counter64"),
        ("1.3.6.1.2.1.31.1.1.1.6.2", 99_000_000_000, "Counter64"),
        ("1.3.6.1.2.1.31.1.1.1.10.1", 2000, "Counter64"),
        ("1.3.6.1.2.1.31.1.1.1.10.2", 88_000_000_000, "Counter64"),
        # ifHighSpeed (Mbps) — 10000 for the 10G interface
        ("1.3.6.1.2.1.31.1.1.1.15.1", 10, "Gauge32"),
        ("1.3.6.1.2.1.31.1.1.1.15.2", 10000, "Gauge32"),
        # ifAlias
        ("1.3.6.1.2.1.31.1.1.1.18.1", "", "OctetString"),
        ("1.3.6.1.2.1.31.1.1.1.18.2", "Uplink", "OctetString"),
    ]

    # The interfaces_list wrapper issues two snmp_table calls; we'll
    # demultiplex by inspecting which OID was requested.
    state = {"if_idx": 0, "ifx_idx": 0}

    async def fake_bulk(_session, oid, _max):
        if oid.startswith("1.3.6.1.2.1.2.2"):
            i = state["if_idx"]
            if i >= len(if_table_rows):
                return [("1.3.6.1.2.1.2.999", None, "endOfMibView")]
            state["if_idx"] += 1
            return [if_table_rows[i]]
        if oid.startswith("1.3.6.1.2.1.31.1.1"):
            i = state["ifx_idx"]
            if i >= len(if_x_table_rows):
                return [("1.3.6.1.2.1.31.999", None, "endOfMibView")]
            state["ifx_idx"] += 1
            return [if_x_table_rows[i]]
        return [("9.9.9", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    result = await interfaces_list(fake_session)
    rows = result["data"]
    assert len(rows) == 2
    by_idx = {r["ifIndex"]: r for r in rows}

    lo = by_idx[1]
    assert lo["ifName"] == "lo"
    assert lo["ifDescr"] == "lo"
    assert lo["ifMtu"] == 65536
    assert lo["ifAdminStatus"] == "up"
    assert lo["ifOperStatus"] == "up"
    assert lo["ifSpeed_bps"] == 10000000
    assert lo["ifSpeed_source"] == "ifSpeed"
    assert lo["counters"]["ifInOctets"] == 1000
    assert lo["counters"]["ifHCInOctets"] == 1000

    eth1 = by_idx[2]
    assert eth1["ifName"] == "ether1"
    assert eth1["ifAlias"] == "Uplink"
    # ifSpeed was saturated → fell back to ifHighSpeed*1e6 = 10 Gbps
    assert eth1["ifSpeed_bps"] == 10_000_000_000
    assert eth1["ifSpeed_source"] == "ifHighSpeed"
    # MAC was formatted from 6 raw bytes.
    assert eth1["ifPhysAddress"] == "90:09:d0:89:56:c4"
    # The saturation warning landed in the warnings list.
    assert any("saturated" in w for w in result["warnings"])
    # HC counter is present and 64-bit-sized.
    assert eth1["counters"]["ifHCInOctets"] == 99_000_000_000


async def test_interfaces_list_status_enum_translation(monkeypatch, fake_session) -> None:
    if_table_rows = [
        ("1.3.6.1.2.1.2.2.1.1.5", 5, "Integer"),
        ("1.3.6.1.2.1.2.2.1.2.5", "ether5", "OctetString"),
        ("1.3.6.1.2.1.2.2.1.7.5", 2, "Integer"),  # admin down
        ("1.3.6.1.2.1.2.2.1.8.5", 7, "Integer"),  # oper lowerLayerDown
    ]

    pos = {"i": 0, "x": 0}

    async def fake_bulk(_session, oid, _max):
        if oid.startswith("1.3.6.1.2.1.2.2"):
            i = pos["i"]
            if i >= len(if_table_rows):
                return [("1.3.6.1.2.1.2.999", None, "endOfMibView")]
            pos["i"] += 1
            return [if_table_rows[i]]
        return [("9.9.9", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    result = await interfaces_list(fake_session)
    assert result["data"][0]["ifAdminStatus"] == "down"
    assert result["data"][0]["ifOperStatus"] == "lowerLayerDown"
