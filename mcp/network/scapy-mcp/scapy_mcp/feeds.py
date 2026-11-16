"""Feed registry — five feeds, two optional, four wiring-discipline signals.

Wiring discipline (mcp-common §7) requires every tool to expose
``feed.entities_count``, ``feed.last_updated_timestamp``, ``feed.errors_total``,
and ``cycles_total``. The :class:`FeedState` Pydantic model backs ``/health``
and ``/readyz``; ``required_feeds_healthy`` aggregates them.

Five feeds:

- ``craft`` (required) — packet construction
- ``dissect`` (required) — packet dissection
- ``pcap`` (required) — PCAP read/write
- ``capture`` (optional) — live BPF capture; degrades when /dev/bpf* missing
- ``transmit`` (optional) — frame emission; master-disabled by default

Required feeds: when any is unhealthy, ``/readyz`` returns 503.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class FeedState(BaseModel):
    """Per-feed observability state."""

    model_config = ConfigDict(extra="forbid")

    name: str
    required: bool = True
    cycles_total: int = 0
    entities_count: int = 0
    last_updated_timestamp: str | None = None
    errors_total: int = 0
    last_error: str | None = None

    def record_cycle(self, *, entities: int = 0, error: str | None = None) -> None:
        self.cycles_total += 1
        if error is not None:
            self.errors_total += 1
            self.last_error = error
            return
        self.entities_count += entities
        self.last_updated_timestamp = datetime.now(UTC).isoformat()

    @property
    def healthy(self) -> bool:
        if not self.required:
            return self.cycles_total > self.errors_total
        if self.cycles_total == 0:
            return False
        if self.cycles_total == self.errors_total:
            return False
        return self.entities_count > 0

    def mark_capability_unavailable(self, reason: str) -> None:
        if self.required:
            raise ValueError(
                f"required feed {self.name!r} cannot be marked unavailable: {reason}",
            )
        self.errors_total += 1
        self.last_error = reason


FEEDS: dict[str, FeedState] = {
    "craft": FeedState(name="craft", required=True),
    "dissect": FeedState(name="dissect", required=True),
    "pcap": FeedState(name="pcap", required=True),
    "capture": FeedState(name="capture", required=False),
    "transmit": FeedState(name="transmit", required=False),
}


def required_feeds_healthy() -> bool:
    """Return True iff every required feed reports healthy."""
    return all(f.healthy for f in FEEDS.values() if f.required)


def as_components() -> list[dict[str, Any]]:
    """Serialize every feed into the wiring-discipline component shape."""
    return [
        {
            "name": f.name,
            "required": f.required,
            "cycles_total": f.cycles_total,
            "entities_count": f.entities_count,
            "last_updated_timestamp": f.last_updated_timestamp,
            "errors_total": f.errors_total,
            "healthy": f.healthy,
        }
        for f in FEEDS.values()
    ]
