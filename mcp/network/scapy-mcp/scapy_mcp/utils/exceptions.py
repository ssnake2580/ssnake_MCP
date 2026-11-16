"""Typed exception hierarchy.

Every error carries structured ``context`` so refusals and dissection
failures can be reported to MCP callers without string-parsing.
"""

from __future__ import annotations

from typing import Any


class ScapyError(Exception):
    """Base error carrying a message plus structured context."""

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = dict(context or {})

    def __str__(self) -> str:
        if not self.context:
            return self.message
        ctx = ", ".join(f"{k}={v}" for k, v in sorted(self.context.items()))
        return f"{self.message} ({ctx})"


class ConfigurationError(ScapyError):
    """Raised when a required setting is missing or malformed."""


class CapabilityUnavailableError(ScapyError):
    """A feed or domain is intentionally disabled (e.g. capture without BPF)."""

    def __init__(self, message: str, *, capability: str, reason: str) -> None:
        super().__init__(message, context={"capability": capability, "reason": reason})
        self.capability = capability
        self.reason = reason


class EmissionRefusedError(ScapyError):
    """A transmit attempt was refused by one of the emission controls."""

    def __init__(self, message: str, *, control: str, reason: str) -> None:
        super().__init__(message, context={"control": control, "reason": reason})
        self.control = control
        self.reason = reason


class DissectionError(ScapyError):
    """Scapy could not dissect the input fully."""

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        offset: int,
        partial_layers: list[str],
    ) -> None:
        super().__init__(
            message,
            context={
                "reason": reason,
                "offset": offset,
                "partial_layers": partial_layers,
            },
        )
        self.reason = reason
        self.offset = offset
        self.partial_layers = partial_layers

    def to_payload(self) -> dict[str, Any]:
        return {
            "error": "dissection_failed",
            "reason": self.reason,
            "offset": self.offset,
            "partial_layers": self.partial_layers.copy(),
        }
