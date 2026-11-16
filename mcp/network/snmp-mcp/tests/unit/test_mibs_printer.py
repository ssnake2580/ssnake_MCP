# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for mibs/printer.py — PRINTER-MIB."""

from __future__ import annotations

import pytest

from snmp_mcp import transport
from snmp_mcp.errors import SnmpUnsupported
from snmp_mcp.mibs.printer import printer_status


async def test_printer_status_happy_path(monkeypatch, fake_session) -> None:
    # Probe returns idle (3).
    probe_resp = [("1.3.6.1.2.1.43.5.1.1.2.1.1", 3, "Integer")]

    supplies_rows = [
        # Supply 1.1: Black Toner — type=3 (toner), unit=19 (percent), max=100, lvl=65
        ("1.3.6.1.2.1.43.11.1.1.1.1.1", 1, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.5.1.1", 3, "Integer"),  # type=toner
        ("1.3.6.1.2.1.43.11.1.1.6.1.1", "Black Toner", "OctetString"),
        ("1.3.6.1.2.1.43.11.1.1.7.1.1", 19, "Integer"),  # unit=percent
        ("1.3.6.1.2.1.43.11.1.1.8.1.1", 100, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.9.1.1", 65, "Integer"),
        # Supply 1.2: drum (opc=9), level -3 (known but unmeasured) — preserved
        ("1.3.6.1.2.1.43.11.1.1.1.1.2", 2, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.5.1.2", 9, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.6.1.2", "Drum", "OctetString"),
        ("1.3.6.1.2.1.43.11.1.1.7.1.2", 19, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.8.1.2", 100, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.9.1.2", -3, "Integer"),
        # Supply 1.3: ink (5), level -2 (unknown) — normalized to None
        ("1.3.6.1.2.1.43.11.1.1.1.1.3", 3, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.5.1.3", 5, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.6.1.3", "Cyan Ink", "OctetString"),
        ("1.3.6.1.2.1.43.11.1.1.7.1.3", 19, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.8.1.3", 100, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.9.1.3", -2, "Integer"),
    ]

    input_rows = [
        ("1.3.6.1.2.1.43.8.2.1.13.1.1", "Tray 1", "OctetString"),
        ("1.3.6.1.2.1.43.8.2.1.9.1.1", 250, "Integer"),
        ("1.3.6.1.2.1.43.8.2.1.10.1.1", 200, "Integer"),
        ("1.3.6.1.2.1.43.8.2.1.11.1.1", 0, "Integer"),
    ]

    output_rows = [
        ("1.3.6.1.2.1.43.9.2.1.13.1.1", "Top", "OctetString"),
        ("1.3.6.1.2.1.43.9.2.1.5.1.1", 100, "Integer"),
        ("1.3.6.1.2.1.43.9.2.1.6.1.1", 0, "Integer"),
        ("1.3.6.1.2.1.43.9.2.1.7.1.1", 0, "Integer"),
    ]

    alert_rows = [
        ("1.3.6.1.2.1.43.18.1.1.2.1.1", 4, "Integer"),  # severity=warning
        ("1.3.6.1.2.1.43.18.1.1.3.1.1", 3, "Integer"),  # training=untrained
        ("1.3.6.1.2.1.43.18.1.1.4.1.1", 11, "Integer"),  # group=markerSupplies
        ("1.3.6.1.2.1.43.18.1.1.7.1.1", 1101, "Integer"),
        ("1.3.6.1.2.1.43.18.1.1.8.1.1", "Black Toner low", "OctetString"),
    ]

    state = {
        "1.3.6.1.2.1.43.11.1": iter(supplies_rows),
        "1.3.6.1.2.1.43.8.2": iter(input_rows),
        "1.3.6.1.2.1.43.9.2": iter(output_rows),
        "1.3.6.1.2.1.43.18.1": iter(alert_rows),
    }

    async def fake_get(_session, _oids):
        return list(probe_resp)

    async def fake_bulk(_session, oid, _max):
        for prefix, it in state.items():
            if oid.startswith(prefix):
                try:
                    return [next(it)]
                except StopIteration:
                    return [(prefix + ".999", None, "endOfMibView")]
        return [("9.9.9", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)

    result = await printer_status(fake_session)
    d = result["data"]
    assert d["printer_status"] == "idle"
    assert len(d["supplies"]) == 3
    by_descr = {s["descr"]: s for s in d["supplies"]}
    assert by_descr["Black Toner"]["type"] == "toner"
    assert by_descr["Black Toner"]["current_level"] == 65
    assert by_descr["Black Toner"]["level_pct"] == 65.0
    # -3 sentinel preserved.
    assert by_descr["Drum"]["current_level"] == -3
    assert by_descr["Drum"]["level_pct"] is None
    # -2 sentinel normalized to None.
    assert by_descr["Cyan Ink"]["current_level"] is None
    assert by_descr["Cyan Ink"]["level_pct"] is None
    # Trays.
    assert d["input_trays"][0]["name"] == "Tray 1"
    assert d["input_trays"][0]["capacity"] == 250
    # Output bins.
    assert d["output_bins"][0]["name"] == "Top"
    # Alerts.
    assert d["alerts"][0]["severity"] == "warning"
    assert d["alerts"][0]["group"] == "markerSupplies"
    assert d["alerts"][0]["description"] == "Black Toner low"


async def test_printer_status_unsupported(monkeypatch, fake_session) -> None:
    """Both supplies and input walks empty → ``SnmpUnsupported``.

    Reflects the post-polish semantics: we no longer pre-flight
    ``prtGeneralPrinterStatus.1.1`` (some printers — notably the OKI
    C530dn over v1 — implement the supplies and input tables but not
    that scalar). The empty-table signal is the real "no PRINTER-MIB".
    """

    async def fake_bulk(_session, oid, _max):
        # Every walk hits endOfMibView immediately → 0 rows everywhere.
        return [(oid + ".0", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    with pytest.raises(SnmpUnsupported):
        await printer_status(fake_session)


async def test_printer_status_v1_no_general_status(monkeypatch, fake_session) -> None:
    """v1 printer with no ``prtGeneralPrinterStatus.1.1`` still returns ok.

    Reproduces the OKI C530dn shape: ``prtMarkerSuppliesTable`` walks
    fine, the post-walk opportunistic GET of ``prtGeneralPrinterStatus``
    raises ``SnmpNoSuchName`` (v1 all-or-nothing). The wrapper should
    swallow the noSuchName, leave ``printer_status=None``, surface the
    supplies, and surface a single warning.
    """
    from snmp_mcp.errors import SnmpNoSuchName

    # Mark the session as v1 so the wrapper exercises the v1 path. The
    # transport layer doesn't actually read this field; the only place
    # version matters here is the (mocked) GET that we make raise.
    fake_session.host_cfg.version = "v1"

    supplies_rows = [
        ("1.3.6.1.2.1.43.11.1.1.1.1.1", 1, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.5.1.1", 3, "Integer"),  # toner
        ("1.3.6.1.2.1.43.11.1.1.6.1.1", "Yellow Toner", "OctetString"),
        ("1.3.6.1.2.1.43.11.1.1.7.1.1", 19, "Integer"),  # percent
        ("1.3.6.1.2.1.43.11.1.1.8.1.1", 100, "Integer"),
        ("1.3.6.1.2.1.43.11.1.1.9.1.1", 10, "Integer"),
    ]

    state = {
        "1.3.6.1.2.1.43.11.1": iter(supplies_rows),
    }

    async def fake_walk_step(_session, oid, *_args):
        # v1 has no GETBULK, so snmp_walk falls back to GETNEXT.
        # Reuse one stepper for both _perform_next and _perform_bulk
        # for resilience against future call-shape changes.
        for prefix, it in state.items():
            if oid.startswith(prefix):
                try:
                    return [next(it)]
                except StopIteration:
                    return [(prefix + ".999", None, "endOfMibView")]
        return [(oid + ".0", None, "endOfMibView")]

    async def fake_get(_session, _oids):
        raise SnmpNoSuchName(
            "noSuchName (errorStatus=2, errorIndex=1)",
            host="testhost",
        )

    monkeypatch.setattr(transport, "_perform_next", fake_walk_step)
    monkeypatch.setattr(transport, "_perform_bulk", fake_walk_step)
    monkeypatch.setattr(transport, "_perform_get", fake_get)

    result = await printer_status(fake_session)
    d = result["data"]
    assert d["printer_status"] is None
    assert len(d["supplies"]) == 1
    assert d["supplies"][0]["descr"] == "Yellow Toner"
    assert d["supplies"][0]["current_level"] == 10
    # The noSuchName-on-prtGeneralPrinterStatus was absorbed as a warning.
    assert any("noSuchName" in w for w in result["warnings"])
