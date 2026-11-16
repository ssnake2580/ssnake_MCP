# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Low-level async SNMP operations.

Wraps pysnmp's v3arch.asyncio hlapi into four primitives used by every
tool in this MCP:

  - ``snmp_get(session, oids)``     — single GET-Request PDU
  - ``snmp_walk(session, root)``    — GETNEXT chain to walk a subtree
  - ``snmp_bulk_walk(session, root, max_repetitions)`` — GETBULK
  - ``snmp_table(session, table_oid)`` — walk + tabularize by row index

pysnmp interactions are intentionally isolated to small helper functions
(``_perform_get``, ``_perform_next``, ``_perform_bulk``) so unit tests can
monkey-patch them and run the higher-level logic without a real engine.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .errors import (
    SnmpAuthFailed,
    SnmpBadValue,
    SnmpEngineMismatch,
    SnmpError,
    SnmpNoSuchName,
    SnmpTimeout,
    SnmpTransportError,
)
from .session import HostSession

logger = logging.getLogger(__name__)

# Sentinel strings pysnmp uses for v2c+ exception varbinds.
_NO_SUCH_INSTANCE = "noSuchInstance"
_NO_SUCH_OBJECT = "noSuchObject"
_END_OF_MIB_VIEW = "endOfMibView"


# --- Public primitives -------------------------------------------------------


async def snmp_get(session: HostSession, oids: list[str]) -> dict[str, Any]:
    """Issue a single GET-Request for one or more OIDs.

    Returns a dict keyed by the requested numeric OID. Missing-varbind
    sentinels (noSuchInstance, noSuchObject) become a ``None`` value with
    an entry in the returned ``warnings`` list.
    """
    if not oids:
        return {"varbinds": {}, "warnings": []}
    var_binds = await _perform_get(session, oids)
    out: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for oid, raw_value, type_name in var_binds:
        if type_name in (_NO_SUCH_INSTANCE, _NO_SUCH_OBJECT):
            out[str(oid)] = {"value": None, "type": type_name}
            warnings.append(f"{oid}: {type_name}")
            continue
        out[str(oid)] = {"value": raw_value, "type": type_name}
    return {"varbinds": out, "warnings": warnings}


async def snmp_walk(
    session: HostSession,
    root_oid: str,
    *,
    use_bulk: bool = False,
    max_repetitions: int = 25,
) -> dict[str, Any]:
    """Walk a subtree via GETNEXT (or GETBULK if ``use_bulk`` is True).

    Terminates when the agent returns ``endOfMibView`` OR when the next OID
    is no longer a descendant of ``root_oid``.
    """
    if use_bulk and session.host_cfg.version == "v1":
        # SNMPv1 does not have GETBULK; degrade silently with a warning.
        use_bulk = False
        warnings = ["SNMPv1 does not support GETBULK; fell back to GETNEXT"]
    else:
        warnings = []

    root_norm = root_oid.lstrip(".")
    rows: list[dict[str, Any]] = []
    current = root_norm

    while True:
        if use_bulk:
            batch = await _perform_bulk(session, current, max_repetitions)
        else:
            batch = await _perform_next(session, current)
        if not batch:
            break
        terminated = False
        for oid, raw_value, type_name in batch:
            oid_s = str(oid).lstrip(".")
            if type_name == _END_OF_MIB_VIEW:
                terminated = True
                break
            if not _is_descendant(oid_s, root_norm):
                terminated = True
                break
            rows.append({"oid": oid_s, "value": raw_value, "type": type_name})
        if terminated:
            break
        current = str(batch[-1][0]).lstrip(".")
        if not _is_descendant(current, root_norm):
            # Last seen OID already escaped the subtree.
            break

    return {"rows": rows, "warnings": warnings}


async def snmp_bulk_walk(
    session: HostSession,
    root_oid: str,
    max_repetitions: int = 25,
) -> dict[str, Any]:
    """Walk a subtree via GETBULK (faster for large tables)."""
    return await snmp_walk(
        session,
        root_oid,
        use_bulk=True,
        max_repetitions=max_repetitions,
    )


async def snmp_table(
    session: HostSession,
    table_oid: str,
    *,
    column_names: dict[str, str] | None = None,
    use_bulk: bool = True,
) -> dict[str, Any]:
    """Walk an SNMP table and tabularize it into rows.

    The walk-result is grouped by row index (the OID suffix below
    ``<table_oid>.1.<column>``). When ``column_names`` is provided, columns
    are also re-emitted under their human-readable names.
    """
    walk = await snmp_walk(
        session,
        table_oid,
        use_bulk=use_bulk,
        max_repetitions=25,
    )
    rows_by_index: dict[str, dict[str, Any]] = {}
    table_root = table_oid.lstrip(".").rstrip(".")
    entry_root = f"{table_root}.1."  # tables use Entry .1 by SMIv2 convention
    column_names = column_names or {}

    for row in walk["rows"]:
        oid = row["oid"]
        if not oid.startswith(entry_root):
            # Some agents return non-entry children before the entry subtree.
            continue
        tail = oid[len(entry_root) :]
        # tail is "<column>.<row_index>"
        col, _, idx = tail.partition(".")
        if not idx:
            continue
        col_oid_full = f"{table_root}.1.{col}"
        row_dict = rows_by_index.setdefault(idx, {"index": idx})
        # Always emit by numeric column OID.
        row_dict[col_oid_full] = row["value"]
        # Also emit by symbolic name when known.
        col_name = column_names.get(col_oid_full)
        if col_name is not None:
            row_dict[col_name] = row["value"]

    out_rows = list(rows_by_index.values())
    out_rows.sort(key=lambda r: _index_sort_key(r["index"]))
    return {
        "table_oid": table_root,
        "rows": out_rows,
        "warnings": walk["warnings"],
    }


# --- Internal helpers --------------------------------------------------------


def _is_descendant(oid: str, root: str) -> bool:
    """Return True if `oid` is within the subtree rooted at `root`.

    Both inputs must be in dotted-numeric form with no leading dot.
    """
    if oid == root:
        return True
    return oid.startswith(root + ".")


def _index_sort_key(idx: str) -> tuple:
    """Sort key for row indices — numeric components compared as integers."""
    parts = idx.split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return tuple(out)


# --- pysnmp glue (kept thin so unit tests can monkey-patch) ------------------


async def _perform_get(
    session: HostSession,
    oids: list[str],
) -> list[tuple[str, Any, str]]:
    """Run a single GET against the agent.

    Returns a list of (oid_str, python_value, type_name) tuples.
    """
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
        ObjectIdentity,
        ObjectType,
        get_cmd,
    )

    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    target = await _resolve_transport(session)
    try:
        error_indication, error_status, error_index, raw_var_binds = await get_cmd(
            session.engine,
            session.auth_data,
            target,
            session.context_data,
            *var_binds,
        )
    except TimeoutError as exc:
        raise SnmpTimeout(
            f"GET timed out for {session.host_cfg.name}",
            host=session.host_cfg.name,
        ) from exc
    except OSError as exc:
        raise SnmpTransportError(
            f"transport error for {session.host_cfg.name}: {exc}",
            host=session.host_cfg.name,
        ) from exc

    _raise_for_indications(session, error_indication, error_status, error_index)
    return [_vb_to_tuple(vb) for vb in raw_var_binds]


async def _perform_next(
    session: HostSession,
    oid: str,
) -> list[tuple[str, Any, str]]:
    """Run a single GETNEXT against the agent."""
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
        ObjectIdentity,
        ObjectType,
        next_cmd,
    )

    target = await _resolve_transport(session)
    try:
        error_indication, error_status, error_index, raw_var_binds = await next_cmd(
            session.engine,
            session.auth_data,
            target,
            session.context_data,
            ObjectType(ObjectIdentity(oid)),
        )
    except TimeoutError as exc:
        raise SnmpTimeout(
            f"GETNEXT timed out for {session.host_cfg.name}",
            host=session.host_cfg.name,
        ) from exc
    except OSError as exc:
        raise SnmpTransportError(
            f"transport error for {session.host_cfg.name}: {exc}",
            host=session.host_cfg.name,
        ) from exc

    _raise_for_indications(session, error_indication, error_status, error_index)
    return [_vb_to_tuple(vb) for vb in raw_var_binds]


async def _perform_bulk(
    session: HostSession,
    oid: str,
    max_repetitions: int,
) -> list[tuple[str, Any, str]]:
    """Run a single GETBULK against the agent."""
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
        ObjectIdentity,
        ObjectType,
        bulk_cmd,
    )

    target = await _resolve_transport(session)
    try:
        error_indication, error_status, error_index, raw_var_binds = await bulk_cmd(
            session.engine,
            session.auth_data,
            target,
            session.context_data,
            0,  # non-repeaters
            max_repetitions,
            ObjectType(ObjectIdentity(oid)),
        )
    except TimeoutError as exc:
        raise SnmpTimeout(
            f"GETBULK timed out for {session.host_cfg.name}",
            host=session.host_cfg.name,
        ) from exc
    except OSError as exc:
        raise SnmpTransportError(
            f"transport error for {session.host_cfg.name}: {exc}",
            host=session.host_cfg.name,
        ) from exc

    _raise_for_indications(session, error_indication, error_status, error_index)
    return [_vb_to_tuple(vb) for vb in raw_var_binds]


async def _resolve_transport(session: HostSession) -> Any:
    """Return a ready-to-use transport target.

    pysnmp 7.x requires building the transport via the async classmethod
    ``UdpTransportTarget.create((host, port), timeout=..., retries=...)``.
    Our ``session.session._build_session`` stashes a ``_LazyUdpTarget``
    sentinel; on first call we call .create() and cache the real target.
    """
    from .session import _LazyUdpTarget  # local to avoid import cycles

    target = session.transport_target
    if isinstance(target, _LazyUdpTarget):
        real = await target.cls.create(
            (target.address, target.port),
            timeout=target.timeout,
            retries=target.retries,
        )
        session.transport_target = real
        return real
    # Already a real transport target.
    if hasattr(target, "transportAddr"):
        return target
    # Defensive fallback: someone passed in an already-coroutine. Await it.
    if asyncio.iscoroutine(target):  # pragma: no cover - shape-dependent
        target = await target
        session.transport_target = target
    return target


def _vb_to_tuple(vb: Any) -> tuple[str, Any, str]:
    """Convert a pysnmp varbind ``(ObjectType, ObjectIdentity)`` to a tuple.

    Returns ``(oid_string, python_value_or_sentinel, type_name)``.
    """
    oid, value = vb
    type_name = type(value).__name__
    # Detect the v2c+ exception-syntax varbinds.
    name_lower = type_name.lower()
    if "nosuchinstance" in name_lower:
        return (str(oid), None, _NO_SUCH_INSTANCE)
    if "nosuchobject" in name_lower:
        return (str(oid), None, _NO_SUCH_OBJECT)
    if "endofmibview" in name_lower:
        return (str(oid), None, _END_OF_MIB_VIEW)
    py_value = _coerce_pysnmp_value(value)
    return (str(oid), py_value, type_name)


def _coerce_pysnmp_value(value: Any) -> Any:
    """Best-effort conversion of a pysnmp value object to a JSON-friendly type.

    OctetString is decoded to UTF-8 with surrogate-escape (preserves bytes
    we can't decode without raising). Integer/Gauge/Counter return Python
    ints. ObjectIdentifier returns its dotted-string form. Anything else
    falls back to ``str()``.
    """
    # Avoid importing pysnmp types at the top of this module — keep tests
    # easy to set up. Pattern-match on attribute / type-name shape.
    type_name = type(value).__name__
    # OctetString and friends expose .prettyPrint() and .__bytes__().
    if hasattr(value, "asOctets"):
        try:
            raw = bytes(value.asOctets())
            return raw.decode("utf-8", errors="surrogateescape")
        except Exception:  # pragma: no cover - defensive
            return str(value)
    # Integer/Gauge/Counter/TimeTicks all behave like ints.
    if type_name in (
        "Integer",
        "Integer32",
        "Counter32",
        "Counter64",
        "Gauge32",
        "Unsigned32",
        "TimeTicks",
    ):
        try:
            return int(value)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return str(value)
    if type_name == "ObjectIdentifier":
        return str(value)
    # Generic fallback.
    return str(value)


def _raise_for_indications(
    session: HostSession,
    error_indication: Any,
    error_status: Any,
    error_index: Any,
) -> None:
    """Translate pysnmp's three-headed error indications into our exceptions."""
    if error_indication:
        msg = str(error_indication)
        lower = msg.lower()
        host = session.host_cfg.name
        if (
            "request timed out" in lower
            or "no response" in lower
            or "no snmp response" in lower
            or "before timeout" in lower
        ):
            raise SnmpTimeout(msg, host=host)
        if "authentication" in lower or "wrongdigest" in lower or "unknownusername" in lower:
            raise SnmpAuthFailed(msg, host=host)
        if "engineid" in lower or "engine id" in lower:
            raise SnmpEngineMismatch(msg, host=host)
        if "unknown" in lower and "host" in lower:
            raise SnmpTransportError(msg, host=host)
        raise SnmpError(msg, host=host)
    if error_status:
        # pysnmp error-status enum: 1=tooBig, 2=noSuchName, 3=badValue,
        # 4=readOnly, 5=genErr, 6=noAccess, 10=wrongType, 17=notWritable
        status_int = int(error_status)
        host = session.host_cfg.name
        details: dict[str, Any] = {
            "error_status": status_int,
            "error_index": int(error_index) if error_index is not None else None,
        }
        if status_int == 2:
            raise SnmpNoSuchName(
                f"noSuchName (errorStatus=2, errorIndex={error_index})",
                host=host,
                details=details,
            )
        if status_int in (3, 10):
            raise SnmpBadValue(
                f"bad value (errorStatus={status_int})",
                host=host,
                details=details,
            )
        raise SnmpError(
            f"SNMP errorStatus={status_int} errorIndex={error_index}",
            host=host,
            details=details,
        )
