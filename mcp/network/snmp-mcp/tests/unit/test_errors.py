# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for the exception hierarchy."""

from __future__ import annotations

from snmp_mcp.errors import (
    ConfigError,
    SnmpAuthFailed,
    SnmpBadValue,
    SnmpEngineMismatch,
    SnmpError,
    SnmpNoSuchName,
    SnmpTimeout,
    SnmpTransportError,
    SnmpUnsupported,
)


def test_each_exception_carries_category_and_host() -> None:
    exc = ConfigError("boom", host="h")
    assert exc.category == "validation"
    assert exc.host == "h"

    assert SnmpAuthFailed("x").category == "auth"
    assert SnmpEngineMismatch("x").category == "auth"
    assert SnmpTimeout("x").category == "timeout"
    assert SnmpNoSuchName("x").category == "validation"
    assert SnmpBadValue("x").category == "validation"
    assert SnmpTransportError("x").category == "network"
    assert SnmpUnsupported("x").category == "unsupported"
    assert SnmpError("x").category == "internal"


def test_to_dict_shape() -> None:
    exc = SnmpTimeout(
        "timed out",
        host="testhost",
        details={"after": 3.0, "retries": 2},
    )
    d = exc.to_dict()
    assert d == {
        "category": "timeout",
        "message": "timed out",
        "host": "testhost",
        "details": {"after": 3.0, "retries": 2},
    }


def test_base_class_is_subclassable() -> None:
    assert issubclass(SnmpAuthFailed, SnmpError)
    assert issubclass(ConfigError, SnmpError)
    assert issubclass(SnmpTimeout, SnmpError)
