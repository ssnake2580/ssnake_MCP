# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for SessionCache (no pysnmp imports — we stub the builder)."""

from __future__ import annotations

from snmp_mcp import session as session_mod
from snmp_mcp.config import HostConfig
from snmp_mcp.session import HostSession, SessionCache


def test_session_cache_caches_per_host(monkeypatch) -> None:
    call_count = {"n": 0}

    def fake_build(host_cfg: HostConfig) -> HostSession:
        call_count["n"] += 1
        return HostSession(
            host_cfg=host_cfg,
            engine=object(),
            auth_data=object(),
            transport_target=object(),
            context_data=object(),
        )

    monkeypatch.setattr(session_mod, "_build_session", fake_build)

    cache = SessionCache()
    cfg = HostConfig(name="a", address="10.0.0.1", version="v2c", community="x")
    s1 = cache.get(cfg)
    s2 = cache.get(cfg)
    assert s1 is s2
    assert call_count["n"] == 1


def test_session_cache_invalidate(monkeypatch) -> None:
    def fake_build(host_cfg: HostConfig) -> HostSession:
        return HostSession(
            host_cfg=host_cfg,
            engine=object(),
            auth_data=object(),
            transport_target=object(),
            context_data=object(),
        )

    monkeypatch.setattr(session_mod, "_build_session", fake_build)

    cache = SessionCache()
    cfg = HostConfig(name="a", address="10.0.0.1", version="v2c", community="x")
    s1 = cache.get(cfg)
    cache.invalidate("a")
    s2 = cache.get(cfg)
    assert s1 is not s2


def test_session_cache_clear(monkeypatch) -> None:
    monkeypatch.setattr(
        session_mod,
        "_build_session",
        lambda cfg: HostSession(
            host_cfg=cfg,
            engine=object(),
            auth_data=object(),
            transport_target=object(),
            context_data=object(),
        ),
    )
    cache = SessionCache()
    cache.get(HostConfig(name="a", address="1", version="v2c", community="x"))
    cache.get(HostConfig(name="b", address="2", version="v2c", community="y"))
    assert len(cache.sessions) == 2
    cache.clear()
    assert cache.sessions == {}
