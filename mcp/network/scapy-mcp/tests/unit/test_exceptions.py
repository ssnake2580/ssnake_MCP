from __future__ import annotations

from scapy_mcp.utils.exceptions import (
    CapabilityUnavailableError,
    ConfigurationError,
    DissectionError,
    EmissionRefusedError,
    ScapyError,
)


def test_configuration_error_is_scapy_error() -> None:
    err = ConfigurationError("missing setting", context={"key": "iface"})
    assert isinstance(err, ScapyError)
    assert err.context == {"key": "iface"}


def test_scapy_error_carries_context() -> None:
    err = ScapyError("boom", context={"foo": "bar"})
    assert err.message == "boom"
    assert err.context == {"foo": "bar"}
    assert "boom" in str(err)


def test_capability_unavailable_specifies_feed() -> None:
    err = CapabilityUnavailableError(
        "capture unavailable", capability="capture", reason="no /dev/bpf*"
    )
    assert err.capability == "capture"
    assert err.reason == "no /dev/bpf*"
    assert "capture" in str(err)


def test_emission_refused_names_control() -> None:
    err = EmissionRefusedError(
        "transmit disabled", control="transmit_enabled", reason="master switch off"
    )
    assert err.control == "transmit_enabled"


def test_dissection_error_carries_offset_and_partial() -> None:
    err = DissectionError(
        "truncated IP header",
        reason="length < 20",
        offset=14,
        partial_layers=["Ether"],
    )
    payload = err.to_payload()
    assert payload["error"] == "dissection_failed"
    assert payload["offset"] == 14
    assert payload["partial_layers"] == ["Ether"]
