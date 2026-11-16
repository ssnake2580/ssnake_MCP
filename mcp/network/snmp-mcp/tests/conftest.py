# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared pytest fixtures.

See DESIGN.md §8 (Testing Strategy). In short:
  - `tests/unit/` stubs the pysnmp glue (``_perform_get`` / ``_perform_next``
    / ``_perform_bulk``) so no network or engine is needed.
  - `tests/integration/` runs against a real SNMP host gated on
    ``SNMP_MCP_LIVE_HOST``; skipped by default.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from snmp_mcp.config import Config, HostConfig, _Defaults
from snmp_mcp.session import HostSession, SessionCache


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live integration tests unless SNMP_MCP_LIVE_HOST is set."""
    if os.environ.get("SNMP_MCP_LIVE_HOST"):
        return
    skip_live = pytest.mark.skip(reason="SNMP_MCP_LIVE_HOST not set")
    for item in items:
        if "integration" in item.nodeid:
            item.add_marker(skip_live)


@pytest.fixture
def host_cfg_v2c() -> HostConfig:
    """A canned HostConfig for an SNMPv2c target at the documentation IP."""
    return HostConfig(
        name="testhost",
        address="192.0.2.10",
        version="v2c",
        community="public",
        port=161,
        timeout=1.0,
        retries=1,
    )


@pytest.fixture
def host_cfg_v3() -> HostConfig:
    """A canned HostConfig for an SNMPv3 target."""
    return HostConfig(
        name="securehost",
        address="192.0.2.11",
        version="v3",
        user="monitor",
        auth_proto="SHA",
        auth_pass="authpass1234",
        priv_proto="AES128",
        priv_pass="privpass1234",
        port=161,
        timeout=1.0,
        retries=1,
    )


@pytest.fixture
def test_config(host_cfg_v2c: HostConfig) -> Config:
    """Config pre-seeded with one v2c host."""
    return Config(defaults=_Defaults(), hosts={"testhost": host_cfg_v2c})


@pytest.fixture
def fake_session(host_cfg_v2c: HostConfig) -> HostSession:
    """A HostSession whose pysnmp fields are inert sentinels.

    Tests in this suite monkey-patch the transport entry points
    (``_perform_get`` / ``_perform_next`` / ``_perform_bulk``) so the
    engine / auth_data / transport_target fields are never dereferenced.
    """
    return HostSession(
        host_cfg=host_cfg_v2c,
        engine=object(),
        auth_data=object(),
        transport_target=_FakeTransportTarget(),
        context_data=object(),
    )


@pytest.fixture
def session_cache() -> SessionCache:
    return SessionCache()


class _FakeTransportTarget:
    """Has the ``transportAddr`` attribute that ``_resolve_transport`` checks."""

    transportAddr: tuple[str, int] = ("192.0.2.10", 161)


@pytest.fixture
def make_varbinds():
    """Helper to build varbind tuples in our transport's intermediate shape.

    Returns a callable: ``make_varbinds([(oid, value, type_name), ...])`` →
    the same list, ready to be returned by a stubbed ``_perform_*``.
    """

    def _make(varbinds: list[tuple[str, Any, str]]) -> list[tuple[str, Any, str]]:
        return list(varbinds)

    return _make
