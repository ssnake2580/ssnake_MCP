# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for mibs/detect.py — device_detect probe."""

from __future__ import annotations

from snmp_mcp import transport
from snmp_mcp.mibs.detect import device_detect


async def test_detect_mikrotik_router(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.14988.1", "ObjectIdentifier"),
            ("1.3.6.1.2.1.1.1.0", "RouterOS CRS312-4C+8XG", "OctetString"),
            ("1.3.6.1.2.1.2.1.0", 15, "Integer"),
            ("1.3.6.1.2.1.25.1.1.0", 1234567, "TimeTicks"),
            # Printer MIB not implemented on a switch.
            ("1.3.6.1.2.1.43.5.1.1.2.1.1", None, "noSuchInstance"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await device_detect(fake_session)
    d = result["data"]
    assert d["vendor_hint"] == "MikroTik"
    assert "SNMPv2-MIB" in d["supported_mibs"]
    assert "IF-MIB" in d["supported_mibs"]
    assert "HOST-RESOURCES-MIB" in d["supported_mibs"]
    assert "PRINTER-MIB" not in d["supported_mibs"]


async def test_detect_epson_printer(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.1248.1.2.2", "ObjectIdentifier"),
            ("1.3.6.1.2.1.1.1.0", "EPSON Built-in 11.42", "OctetString"),
            ("1.3.6.1.2.1.2.1.0", 2, "Integer"),
            ("1.3.6.1.2.1.25.1.1.0", 1234567, "TimeTicks"),
            ("1.3.6.1.2.1.43.5.1.1.2.1.1", 3, "Integer"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await device_detect(fake_session)
    d = result["data"]
    assert d["vendor_hint"] == "Seiko Epson"
    assert d["supported_mibs"] == ["SNMPv2-MIB", "IF-MIB", "HOST-RESOURCES-MIB", "PRINTER-MIB"]


async def test_detect_v1_partial_oid_support(monkeypatch, fake_session) -> None:
    """v1 device that fails one probe OID with ``noSuchName``.

    Reproduces the OKI C530dn shape: SNMPv1 returns ``noSuchName`` for
    the whole multi-OID GET if any single OID is unimplemented. The
    fix issues one GET per OID and absorbs the ``noSuchName`` as an
    absent varbind, so detection still succeeds for the OIDs that DO
    answer.
    """
    from snmp_mcp.errors import SnmpNoSuchName

    fake_session.host_cfg.version = "v1"

    # Map of OID → response, mirroring how a minimally-conformant v1
    # printer agent might answer each probe.
    responses: dict[str, list[tuple[str, object, str]] | type[SnmpNoSuchName]] = {
        "1.3.6.1.2.1.1.2.0": [
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.2001.1.1", "ObjectIdentifier"),
        ],
        "1.3.6.1.2.1.1.1.0": [
            ("1.3.6.1.2.1.1.1.0", "Generic v1 printer", "OctetString"),
        ],
        "1.3.6.1.2.1.2.1.0": [
            ("1.3.6.1.2.1.2.1.0", 1, "Integer"),
        ],
        # HOST-RESOURCES-MIB not implemented — v1 returns errorStatus=2.
        "1.3.6.1.2.1.25.1.1.0": SnmpNoSuchName,
        "1.3.6.1.2.1.43.5.1.1.2.1.1": [
            ("1.3.6.1.2.1.43.5.1.1.2.1.1", 3, "Integer"),
        ],
    }

    async def fake_get(_session, oids):
        # The v1 path issues one GET per OID, so we only ever see len==1.
        assert len(oids) == 1, "v1 path must issue per-OID GETs"
        oid = oids[0]
        resp = responses[oid]
        if resp is SnmpNoSuchName:
            raise SnmpNoSuchName(
                f"noSuchName (errorStatus=2, errorIndex=1) for {oid}",
                host="testhost",
            )
        return list(resp)  # type: ignore[arg-type]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await device_detect(fake_session)
    d = result["data"]
    assert d["sys_object_id"] == "1.3.6.1.4.1.2001.1.1"
    assert d["sys_descr"] == "Generic v1 printer"
    assert "SNMPv2-MIB" in d["supported_mibs"]
    assert "IF-MIB" in d["supported_mibs"]
    # HOST-RESOURCES-MIB absent (the per-OID GET absorbed the noSuchName).
    assert "HOST-RESOURCES-MIB" not in d["supported_mibs"]
    assert "PRINTER-MIB" in d["supported_mibs"]
    # The synthetic noSuchInstance warning is surfaced.
    assert any("noSuchName" in w for w in result["warnings"])


async def test_detect_bare_switch_no_host_resources(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9.1.123", "ObjectIdentifier"),
            ("1.3.6.1.2.1.1.1.0", "Cisco IOS", "OctetString"),
            ("1.3.6.1.2.1.2.1.0", 48, "Integer"),
            # HOST-RESOURCES not implemented on a bare switch.
            ("1.3.6.1.2.1.25.1.1.0", None, "noSuchInstance"),
            ("1.3.6.1.2.1.43.5.1.1.2.1.1", None, "noSuchInstance"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    result = await device_detect(fake_session)
    d = result["data"]
    assert d["vendor_hint"] == "Cisco"
    assert "HOST-RESOURCES-MIB" not in d["supported_mibs"]
    assert "PRINTER-MIB" not in d["supported_mibs"]
