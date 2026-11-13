"""Input validation shared by every tool.

Tool arguments are LLM-driven and must be treated as adversarial: nothing
here ever builds a shell string (subprocess calls always pass argv lists),
but sizes/counts/hostnames are still bounds-checked so a single tool call
cannot become an amplification vector (e.g. an unbounded ping count) or a
malformed argv0 for the wrapped binary.
"""

import ipaddress
import re

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
_TIMEZONE_RE = re.compile(r"^[A-Za-z0-9+_-]+(/[A-Za-z0-9+_-]+){0,2}$")


def validate_target(value: str) -> str:
    """Return value unchanged if it is a plausible hostname or IP literal.

    Raises ValueError otherwise. Deliberately permissive about *what* the
    name resolves to (that is the point of the tool) — this only rejects
    input that could not be a real target at all (empty, whitespace,
    shell metacharacters, embedded newlines).
    """
    target = value.strip()
    if not target or len(target) > 253:
        raise ValueError("target must be a non-empty hostname or IP address")
    if any(c.isspace() for c in target):
        raise ValueError("target must not contain whitespace")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(target):
        raise ValueError(f"not a valid hostname or IP address: {value!r}")
    return target


def validate_port(value: int) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def validate_timezone(value: str) -> str:
    """Return value unchanged if it has the shape of an IANA timezone key.

    ZoneInfo resolves the key against files on disk, so it is bounded and
    shape-checked here before being handed over: no absolute paths, no
    traversal, no whitespace. Whether the zone actually exists is left to
    ZoneInfo — this only rejects input that could not be a zone name at all.
    """
    zone = value.strip()
    if not zone or len(zone) > 64:
        raise ValueError("timezone must be a non-empty IANA name, e.g. 'Asia/Tokyo'")
    if not _TIMEZONE_RE.match(zone):
        raise ValueError(f"not a valid IANA timezone name: {value!r}")
    return zone
