# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for mibs/system.py — SNMPv2-MIB::system group."""

from __future__ import annotations

from snmp_mcp import oids, transport
from snmp_mcp.mibs.system import system_info


async def test_system_info_happy_path(monkeypatch, fake_session) -> None:
    async def fake_get(_session, requested):
        # pysnmp normalizes the request order; reply with values in the
        # order our caller passed in.
        return [
            ("1.3.6.1.2.1.1.1.0", "RouterOS CRS312-4C+8XG", "OctetString"),
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.14988.1", "ObjectIdentifier"),
            ("1.3.6.1.2.1.1.3.0", 12345678, "TimeTicks"),
            ("1.3.6.1.2.1.1.4.0", "admin@example.com", "OctetString"),
            ("1.3.6.1.2.1.1.5.0", "crs312", "OctetString"),
            ("1.3.6.1.2.1.1.6.0", "rack 1", "OctetString"),
            ("1.3.6.1.2.1.1.7.0", 78, "Integer"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await system_info(fake_session)
    d = result["data"]
    assert d["sysName"] == "crs312"
    assert d["sysDescr"] == "RouterOS CRS312-4C+8XG"
    assert d["sysObjectID"] == "1.3.6.1.4.1.14988.1"
    assert d["sysUpTime"] == 12345678
    assert d["sysUpTime_seconds"] == 123456.78
    assert d["sysServices"] == 78


async def test_system_info_handles_missing_scalars(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _requested):
        return [
            ("1.3.6.1.2.1.1.1.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.42", "ObjectIdentifier"),
            ("1.3.6.1.2.1.1.3.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.1.4.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.1.5.0", "boxname", "OctetString"),
            ("1.3.6.1.2.1.1.6.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.1.7.0", None, "noSuchInstance"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await system_info(fake_session)
    d = result["data"]
    assert d["sysName"] == "boxname"
    assert d["sysDescr"] is None
    assert d["sysUpTime"] is None
    assert d["sysUpTime_seconds"] is None
    # Each missing scalar appends a warning.
    assert len(result["warnings"]) == 5


async def test_system_info_uses_correct_oids() -> None:
    # Sanity check — make sure the constants we use are the real RFC ones.
    assert oids.SYS_NAME == "1.3.6.1.2.1.1.5.0"
    assert oids.SYS_OBJECT_ID == "1.3.6.1.2.1.1.2.0"
    assert oids.SYS_UP_TIME == "1.3.6.1.2.1.1.3.0"
