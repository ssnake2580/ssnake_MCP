# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for the OID resolver + vendor-hint mapping."""

from __future__ import annotations

import pytest

from snmp_mcp import oids


def test_resolve_numeric_passes_through() -> None:
    assert oids.resolve_oid("1.3.6.1.2.1.1.5.0") == "1.3.6.1.2.1.1.5.0"


def test_resolve_strips_leading_dot() -> None:
    assert oids.resolve_oid(".1.3.6.1.2.1.1.5.0") == "1.3.6.1.2.1.1.5.0"


def test_resolve_symbolic_known() -> None:
    assert oids.resolve_oid("SNMPv2-MIB::sysName.0") == oids.SYS_NAME
    assert oids.resolve_oid("IF-MIB::ifNumber.0") == oids.IF_NUMBER


def test_resolve_symbolic_unknown_raises() -> None:
    with pytest.raises(ValueError):
        oids.resolve_oid("MADE-UP-MIB::something.0")


def test_resolve_empty_raises() -> None:
    with pytest.raises(ValueError):
        oids.resolve_oid("")


def test_vendor_from_mikrotik() -> None:
    assert oids.vendor_from_sys_object_id("1.3.6.1.4.1.14988.1") == "MikroTik"


def test_vendor_from_epson() -> None:
    assert oids.vendor_from_sys_object_id("1.3.6.1.4.1.1248.1.2.2") == "Seiko Epson"


def test_vendor_from_oki() -> None:
    assert oids.vendor_from_sys_object_id("1.3.6.1.4.1.8741.1") == "OKI Data"


def test_vendor_from_synology() -> None:
    assert oids.vendor_from_sys_object_id("1.3.6.1.4.1.6574.1") == "Synology"


def test_vendor_from_non_enterprise_oid() -> None:
    # Doesn't start with .1.3.6.1.4.1 — not an enterprise OID.
    assert oids.vendor_from_sys_object_id("1.3.6.1.2.1.1") == "unknown"


def test_vendor_from_unknown_enterprise() -> None:
    # Made-up enterprise number; should fall through.
    assert oids.vendor_from_sys_object_id("1.3.6.1.4.1.99999999.1") == "unknown"


def test_known_status_enum_lookups() -> None:
    assert oids.IF_STATUS_NAMES[1] == "up"
    assert oids.IF_STATUS_NAMES[2] == "down"
    assert oids.IF_STATUS_NAMES[7] == "lowerLayerDown"


def test_storage_type_name_known_lookup() -> None:
    assert oids.HR_STORAGE_TYPE_NAMES["1.3.6.1.2.1.25.2.1.2"] == "ram"
    assert oids.HR_STORAGE_TYPE_NAMES["1.3.6.1.2.1.25.2.1.4"] == "fixed_disk"
