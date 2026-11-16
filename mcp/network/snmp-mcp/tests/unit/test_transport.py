# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for the generic SNMP primitives in transport.py.

The pysnmp glue (``_perform_get`` / ``_perform_next`` / ``_perform_bulk``)
is stubbed via monkeypatch so no engine or network is needed.
"""

from __future__ import annotations

import pytest

from snmp_mcp import transport
from snmp_mcp.errors import SnmpError, SnmpTimeout
from snmp_mcp.transport import (
    _is_descendant,
    snmp_bulk_walk,
    snmp_get,
    snmp_table,
    snmp_walk,
)


def test_is_descendant_truth_table() -> None:
    assert _is_descendant("1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2")
    assert _is_descendant("1.3.6.1.2.1.2.2", "1.3.6.1.2.1.2.2")
    assert not _is_descendant("1.3.6.1.2.1.3", "1.3.6.1.2.1.2.2")
    # Prefix-trick must not match: .2.20 is not under .2.2.
    assert not _is_descendant("1.3.6.1.2.1.2.20", "1.3.6.1.2.1.2.2")


async def test_get_happy_path(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.1.5.0", "crs312", "OctetString"),
            ("1.3.6.1.2.1.1.3.0", 12345678, "TimeTicks"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    out = await snmp_get(fake_session, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
    assert out["warnings"] == []
    assert out["varbinds"]["1.3.6.1.2.1.1.5.0"]["value"] == "crs312"
    assert out["varbinds"]["1.3.6.1.2.1.1.3.0"]["value"] == 12345678


async def test_get_empty_oid_list_short_circuits(fake_session) -> None:
    out = await snmp_get(fake_session, [])
    assert out == {"varbinds": {}, "warnings": []}


async def test_get_marks_missing_varbinds(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        return [
            ("1.3.6.1.2.1.1.5.0", "crs312", "OctetString"),
            ("1.3.6.1.2.1.99.0", None, "noSuchInstance"),
        ]

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    out = await snmp_get(fake_session, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.99.0"])
    assert out["varbinds"]["1.3.6.1.2.1.99.0"]["value"] is None
    assert "noSuchInstance" in out["warnings"][0]


async def test_get_timeout_propagates(monkeypatch, fake_session) -> None:
    async def fake_get(_session, _oids):
        raise SnmpTimeout("boom", host="testhost")

    monkeypatch.setattr(transport, "_perform_get", fake_get)
    with pytest.raises(SnmpTimeout):
        await snmp_get(fake_session, ["1.3.6.1.2.1.1.5.0"])


async def test_walk_terminates_on_end_of_mib_view(monkeypatch, fake_session) -> None:
    calls = []

    async def fake_next(_session, oid):
        calls.append(oid)
        if len(calls) == 1:
            return [("1.3.6.1.2.1.1.5.0", "name1", "OctetString")]
        if len(calls) == 2:
            return [("1.3.6.1.2.1.1.5.1", "name2", "OctetString")]
        # Third call: agent signals end of MIB view.
        return [("1.3.6.1.2.1.1.999", None, "endOfMibView")]

    monkeypatch.setattr(transport, "_perform_next", fake_next)
    out = await snmp_walk(fake_session, "1.3.6.1.2.1.1")
    assert len(out["rows"]) == 2
    assert [r["value"] for r in out["rows"]] == ["name1", "name2"]


async def test_walk_terminates_when_oid_leaves_subtree(monkeypatch, fake_session) -> None:
    calls = []

    async def fake_next(_session, oid):
        calls.append(oid)
        if len(calls) == 1:
            return [("1.3.6.1.2.1.1.5.0", "in_subtree", "OctetString")]
        # Second call: response is outside the subtree.
        return [("1.3.6.1.2.1.2.1.0", "out_of_subtree", "Integer")]

    monkeypatch.setattr(transport, "_perform_next", fake_next)
    out = await snmp_walk(fake_session, "1.3.6.1.2.1.1")
    assert [r["value"] for r in out["rows"]] == ["in_subtree"]


async def test_bulk_walk_falls_back_on_v1(monkeypatch, host_cfg_v2c) -> None:
    from snmp_mcp.session import HostSession

    host_cfg_v2c.version = "v1"
    session = HostSession(
        host_cfg=host_cfg_v2c,
        engine=object(),
        auth_data=object(),
        transport_target=type("X", (), {"transportAddr": ()})(),
        context_data=object(),
    )

    async def fake_next(_session, _oid):
        return [("1.3.6.1.2.1.1.999", None, "endOfMibView")]

    async def must_not_be_called(*_a, **_kw):
        raise AssertionError("bulk path should not be used on v1")

    monkeypatch.setattr(transport, "_perform_next", fake_next)
    monkeypatch.setattr(transport, "_perform_bulk", must_not_be_called)

    out = await snmp_bulk_walk(session, "1.3.6.1.2.1.1")
    assert out["warnings"] and "fell back" in out["warnings"][0]


async def test_bulk_walk_uses_bulk_on_v2c(monkeypatch, fake_session) -> None:
    bulk_called = []
    next_called = []

    async def fake_bulk(_session, oid, _max):
        bulk_called.append(oid)
        # Return endOfMibView to terminate on first call.
        return [("1.3.6.1.2.1.1.999", None, "endOfMibView")]

    async def fake_next(*_a, **_kw):
        next_called.append(_a)
        return []

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    monkeypatch.setattr(transport, "_perform_next", fake_next)

    await snmp_bulk_walk(fake_session, "1.3.6.1.2.1.1")
    assert bulk_called and not next_called


async def test_table_tabularizes_by_index(monkeypatch, fake_session) -> None:
    # Mock a 2-row, 2-column subtree under ifTable (.1.3.6.1.2.1.2.2)
    # Columns: ifIndex(.1.1) and ifDescr(.1.2)
    rows = [
        ("1.3.6.1.2.1.2.2.1.1.1", 1, "Integer"),
        ("1.3.6.1.2.1.2.2.1.1.2", 2, "Integer"),
        ("1.3.6.1.2.1.2.2.1.2.1", "lo", "OctetString"),
        ("1.3.6.1.2.1.2.2.1.2.2", "ether1", "OctetString"),
    ]
    pointer = {"i": 0}

    async def fake_bulk(_session, _oid, _max):
        if pointer["i"] >= len(rows):
            return [("1.3.6.1.2.1.2.999", None, "endOfMibView")]
        out = [rows[pointer["i"]]]
        pointer["i"] += 1
        return out

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)

    column_names = {
        "1.3.6.1.2.1.2.2.1.1": "ifIndex",
        "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    }
    out = await snmp_table(
        fake_session,
        "1.3.6.1.2.1.2.2",
        column_names=column_names,
    )
    assert out["table_oid"] == "1.3.6.1.2.1.2.2"
    assert len(out["rows"]) == 2
    by_index = {r["index"]: r for r in out["rows"]}
    assert by_index["1"]["ifIndex"] == 1
    assert by_index["1"]["ifDescr"] == "lo"
    assert by_index["2"]["ifDescr"] == "ether1"


async def test_table_unknown_columns_keyed_by_oid(monkeypatch, fake_session) -> None:
    rows = [
        ("1.3.6.1.99.1.1.1", 42, "Integer"),
    ]
    pointer = {"i": 0}

    async def fake_bulk(_session, _oid, _max):
        if pointer["i"] >= len(rows):
            return [("1.3.6.1.99.999", None, "endOfMibView")]
        out = [rows[pointer["i"]]]
        pointer["i"] += 1
        return out

    monkeypatch.setattr(transport, "_perform_bulk", fake_bulk)
    out = await snmp_table(fake_session, "1.3.6.1.99")
    assert out["rows"][0]["index"] == "1"
    # Unknown column keyed numerically.
    assert out["rows"][0]["1.3.6.1.99.1.1"] == 42


def test_vb_to_tuple_handles_sentinel_classes() -> None:
    class NoSuchInstance:
        pass

    class EndOfMibView:
        pass

    # The vb shape is (oid, value).
    out = transport._vb_to_tuple(("1.3.6.1.2.1.99", NoSuchInstance()))
    assert out == ("1.3.6.1.2.1.99", None, "noSuchInstance")

    out = transport._vb_to_tuple(("1.3.6.1.2.1.999", EndOfMibView()))
    assert out == ("1.3.6.1.2.1.999", None, "endOfMibView")


def test_vb_to_tuple_coerces_integer_like() -> None:
    class FakeCounter32:
        def __init__(self, v: int) -> None:
            self._v = v

        def __int__(self) -> int:
            return self._v

    # Rename the type to mirror what pysnmp emits.
    FakeCounter32.__name__ = "Counter32"
    out = transport._vb_to_tuple(("1.3.6.1.2.1.2.2.1.10.1", FakeCounter32(123456)))
    assert out == ("1.3.6.1.2.1.2.2.1.10.1", 123456, "Counter32")


def test_raise_for_indications_translates(fake_session) -> None:
    from snmp_mcp.errors import (
        SnmpAuthFailed,
        SnmpBadValue,
        SnmpEngineMismatch,
        SnmpNoSuchName,
    )

    # error_indication: timeout
    with pytest.raises(SnmpTimeout):
        transport._raise_for_indications(fake_session, "Request timed out", 0, 0)

    # error_indication: auth
    with pytest.raises(SnmpAuthFailed):
        transport._raise_for_indications(
            fake_session,
            "Authentication failure: wrongDigests",
            0,
            0,
        )

    # error_indication: engine-id mismatch
    with pytest.raises(SnmpEngineMismatch):
        transport._raise_for_indications(
            fake_session,
            "Unknown engineID for this user",
            0,
            0,
        )

    # error_indication: generic
    with pytest.raises(SnmpError):
        transport._raise_for_indications(fake_session, "Some other failure", 0, 0)

    # error_status=2 (noSuchName)
    with pytest.raises(SnmpNoSuchName):
        transport._raise_for_indications(fake_session, None, _Errstatus(2), 1)

    # error_status=3 (badValue)
    with pytest.raises(SnmpBadValue):
        transport._raise_for_indications(fake_session, None, _Errstatus(3), 1)


class _Errstatus:
    """Stand-in for pysnmp errorStatus int-like object."""

    def __init__(self, v: int) -> None:
        self._v = v

    def __int__(self) -> int:
        return self._v

    def __bool__(self) -> bool:
        return self._v != 0


def test_index_sort_key_numeric() -> None:
    from snmp_mcp.transport import _index_sort_key

    a = _index_sort_key("2")
    b = _index_sort_key("10")
    assert a < b  # numeric ordering, not lexicographic
