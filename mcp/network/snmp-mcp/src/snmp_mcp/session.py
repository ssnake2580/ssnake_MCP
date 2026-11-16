# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Per-host SNMP session cache.

Holds one pysnmp SnmpEngine + credentials + transport target per host name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import HostConfig
from .errors import ConfigError


@dataclass
class _LazyUdpTarget:
    """Holds the args needed to build a pysnmp UdpTransportTarget on first use.

    pysnmp 7.x exposes ``UdpTransportTarget.create((host, port), timeout=...,
    retries=...)`` as an async classmethod that resolves DNS. We can't call
    it from a sync ``_build_session`` (no event loop), so we stash the args
    and let ``transport._resolve_transport`` call .create() inside an
    async context, caching the result back on the session.
    """

    cls: Any
    address: str
    port: int
    timeout: float
    retries: int


@dataclass
class HostSession:
    """Cached pysnmp objects for one host."""

    host_cfg: HostConfig
    engine: Any  # pysnmp SnmpEngine
    auth_data: Any  # CommunityData | UsmUserData
    transport_target: Any  # UdpTransportTarget
    context_data: Any  # ContextData

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"HostSession(host={self.host_cfg.name!r}, version={self.host_cfg.version!r})"


@dataclass
class SessionCache:
    """Process-wide cache of HostSessions, keyed by host name."""

    sessions: dict[str, HostSession] = field(default_factory=dict)

    def get(self, host_cfg: HostConfig) -> HostSession:
        """Return the cached session for `host_cfg.name`, building it on miss."""
        s = self.sessions.get(host_cfg.name)
        if s is not None:
            return s
        s = _build_session(host_cfg)
        self.sessions[host_cfg.name] = s
        return s

    def invalidate(self, host: str) -> None:
        self.sessions.pop(host, None)

    def clear(self) -> None:
        self.sessions.clear()


def _build_session(host_cfg: HostConfig) -> HostSession:
    """Construct a HostSession by importing pysnmp lazily.

    pysnmp is imported here (not at module top) so that tests can monkey-patch
    or stub it out without paying its import cost up front.
    """
    # Late import to keep test isolation easy and avoid asyncio side effects.
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
        CommunityData,
        ContextData,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
        usmNoPrivProtocol,
    )

    engine = SnmpEngine()
    auth_data = _build_auth_data(
        host_cfg,
        CommunityData=CommunityData,
        UsmUserData=UsmUserData,
        auth_proto_map={
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        },
        priv_proto_map={
            "DES": usmDESPrivProtocol,
            "3DES": usm3DESEDEPrivProtocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        },
        no_auth=usmNoAuthProtocol,
        no_priv=usmNoPrivProtocol,
    )
    # pysnmp 7.x requires the async factory `UdpTransportTarget.create()` —
    # the bare constructor reorders its args and chokes on `timeout=` /
    # `retries=` kwargs. Stash the factory inputs here; the transport
    # module's `_resolve_transport` calls .create() on first use.
    transport_target = _LazyUdpTarget(
        cls=UdpTransportTarget,
        address=host_cfg.address,
        port=host_cfg.port,
        timeout=host_cfg.timeout,
        retries=host_cfg.retries,
    )
    context_data = ContextData(contextName=host_cfg.context or "")
    return HostSession(
        host_cfg=host_cfg,
        engine=engine,
        auth_data=auth_data,
        transport_target=transport_target,
        context_data=context_data,
    )


def _build_auth_data(
    host_cfg: HostConfig,
    *,
    CommunityData: Any,
    UsmUserData: Any,
    auth_proto_map: dict[str, Any],
    priv_proto_map: dict[str, Any],
    no_auth: Any,
    no_priv: Any,
) -> Any:
    """Construct the pysnmp auth-data object appropriate for the host."""
    if host_cfg.version == "v1":
        # mpModel=0 selects v1; community is required.
        if not host_cfg.community:
            raise ConfigError(
                f"host {host_cfg.name!r} (v1) missing community",
                host=host_cfg.name,
            )
        return CommunityData(host_cfg.community, mpModel=0)
    if host_cfg.version == "v2c":
        if not host_cfg.community:
            raise ConfigError(
                f"host {host_cfg.name!r} (v2c) missing community",
                host=host_cfg.name,
            )
        return CommunityData(host_cfg.community, mpModel=1)
    if host_cfg.version == "v3":
        if not host_cfg.user:
            raise ConfigError(
                f"host {host_cfg.name!r} (v3) missing user",
                host=host_cfg.name,
            )
        auth_proto = auth_proto_map[host_cfg.auth_proto] if host_cfg.auth_proto else no_auth
        priv_proto = priv_proto_map[host_cfg.priv_proto] if host_cfg.priv_proto else no_priv
        return UsmUserData(
            host_cfg.user,
            authKey=host_cfg.auth_pass,
            privKey=host_cfg.priv_pass,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    raise ConfigError(
        f"host {host_cfg.name!r} has unsupported version {host_cfg.version!r}",
        host=host_cfg.name,
    )
