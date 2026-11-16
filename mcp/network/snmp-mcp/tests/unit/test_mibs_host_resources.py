# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for mibs/host_resources.py — HOST-RESOURCES-MIB."""

from __future__ import annotations

import pytest

from snmp_mcp import transport
from snmp_mcp.errors import SnmpUnsupported
from snmp_mcp.mibs.host_resources import host_resources


async def test_host_resources_happy_path(monkeypatch, fake_session) -> None:
    scalars = [
        ("1.3.6.1.2.1.25.1.1.0", 9999, "TimeTicks"),
        ("1.3.6.1.2.1.25.1.2.0", "2026-05-26T20:00:00", "OctetString"),
        ("1.3.6.1.2.1.25.1.6.0", 142, "Integer"),
        ("1.3.6.1.2.1.25.1.5.0", 1, "Integer"),
        ("1.3.6.1.2.1.25.2.2.0", 16_777_216, "Integer"),
    ]
    cpu_walk_rows = [
        ("1.3.6.1.2.1.25.3.3.1.2.1", 12, "Integer"),
        ("1.3.6.1.2.1.25.3.3.1.2.2", 8, "Integer"),
    ]
    storage_rows = [
        # Storage row 1: RAM (.1.3.6.1.2.1.25.2.1.2)
        ("1.3.6.1.2.1.25.2.3.1.1.1", 1, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.2.1", "1.3.6.1.2.1.25.2.1.2", "ObjectIdentifier"),
        ("1.3.6.1.2.1.25.2.3.1.3.1", "Physical memory", "OctetString"),
        ("1.3.6.1.2.1.25.2.3.1.4.1", 1024, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.5.1", 16_777_216, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.6.1", 8_388_608, "Integer"),
        # Storage row 2: fixed_disk
        ("1.3.6.1.2.1.25.2.3.1.1.2", 2, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.2.2", "1.3.6.1.2.1.25.2.1.4", "ObjectIdentifier"),
        ("1.3.6.1.2.1.25.2.3.1.3.2", "/", "OctetString"),
        ("1.3.6.1.2.1.25.2.3.1.4.2", 4096, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.5.2", 25_000_000, "Integer"),
        ("1.3.6.1.2.1.25.2.3.1.6.2", 12_500_000, "Integer"),
    ]

    pos_cpu = {"i": 0}
    pos_st = {"i": 0}

    async def fake_get(_session, _oids):
        return list(scalars)

    async def fake_bulk(_session, oid, _max):
        if oid.startswith("1.3.6.1.2.1.25.3.3.1.2"):
            i = pos_cpu["i"]
            if i >= len(cpu_walk_rows):
                return [("1.3.6.1.2.1.25.3.999", None, "endOfMibView")]
            pos_cpu["i"] += 1
            return [cpu_walk_rows[i]]
        if oid.startswith("1.3.6.1.2.1.25.2.3"):
            i = pos_st["i"]
            if i >= len(storage_rows):
                return [("1.3.6.1.2.1.25.999", None, "endOfMibView")]
            pos_st["i"] += 1
            return [storage_rows[i]]
        return [("9.9.9", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    result = await host_resources(fake_session)
    d = result["data"]
    assert d["hrSystemUptime_centiseconds"] == 9999
    assert d["hrSystemUptime_seconds"] == 99.99
    assert d["hrSystemProcesses"] == 142
    assert d["hrSystemNumUsers"] == 1
    assert d["memory"]["physical_kb"] == 16_777_216
    assert d["cpu_load_pct"] == [12, 8]
    assert len(d["storage"]) == 2
    ram = next(s for s in d["storage"] if s["type"] == "ram")
    assert ram["size_bytes"] == 1024 * 16_777_216
    assert ram["used_bytes"] == 1024 * 8_388_608
    disk = next(s for s in d["storage"] if s["type"] == "fixed_disk")
    assert disk["size_bytes"] == 4096 * 25_000_000


async def test_host_resources_unsupported(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.25.1.1.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.25.1.2.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.25.1.6.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.25.1.5.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.25.2.2.0", None, "noSuchInstance"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    with pytest.raises(SnmpUnsupported):
        await host_resources(fake_session)
