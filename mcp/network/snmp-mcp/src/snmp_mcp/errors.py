# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Exception hierarchy for snmp-mcp.

SNMP error conditions map to specific exception classes (see DESIGN.md §4).
Tool-level callers see one of:

  - ConfigError: misconfiguration (missing community, unknown host, bad TOML)
  - SnmpAuthFailed: v3 auth failure (wrong digest, unknown user) — no retry
  - SnmpEngineMismatch: v3 engine-ID mismatch — discover-and-retry once
  - SnmpTimeout: request timed out after configured retries
  - SnmpNoSuchName: v1 noSuchName error — varbind missing
  - SnmpBadValue: v1/v2c bad value or wrong type
  - SnmpTransportError: socket-level failure
  - SnmpUnsupported: agent does not implement the requested MIB
  - SnmpError: generic fallback for unmapped conditions
"""

from __future__ import annotations

from typing import Any


class SnmpError(Exception):
    """Base class for SNMP-related failures."""

    category: str = "internal"

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.host = host
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "message": self.message,
            "host": self.host,
            "details": self.details,
        }


class ConfigError(SnmpError):
    """Misconfiguration: missing community, unknown host, malformed file."""

    category = "validation"


class SnmpAuthFailed(SnmpError):
    """SNMPv3 USM auth failed (unknown user, wrong digest, etc.)."""

    category = "auth"


class SnmpEngineMismatch(SnmpError):
    """SNMPv3 authoritative engine-ID mismatch."""

    category = "auth"


class SnmpTimeout(SnmpError):
    """Request timed out after configured retries."""

    category = "timeout"


class SnmpNoSuchName(SnmpError):
    """SNMPv1 noSuchName error (errorStatus=2)."""

    category = "validation"


class SnmpBadValue(SnmpError):
    """SNMPv1/v2c bad-value or wrong-type error."""

    category = "validation"


class SnmpTransportError(SnmpError):
    """Network-level failure (connection refused, host unreachable, etc.)."""

    category = "network"


class SnmpUnsupported(SnmpError):
    """Agent does not implement the requested MIB / table / OID subtree."""

    category = "unsupported"
