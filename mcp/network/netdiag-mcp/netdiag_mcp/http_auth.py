"""Optional Authorization header for http_get, scoped by URL prefix.

``NETDIAG_HTTP_AUTH`` holds a JSON object that maps an https URL prefix to the
value of the Authorization header sent to URLs under it, e.g.::

    NETDIAG_HTTP_AUTH='{"https://reports.example.ac.jp/daily/": "Bearer <token>"}'

The header is chosen per request, after every redirect hop, by comparing the
parsed URL (scheme, host, port, path) with each prefix -- never by raw string
prefix, so ``https://reports.example.ac.jp.evil.example/`` or
``https://reports.example.ac.jp@evil.example/`` cannot pick it up. Only https
URLs ever carry it. Header values are never returned, logged or put into an
error message; prefixes are not secret and are reported by health_check.

The variable is read from the process environment only (no config file): on a
host that runs several instances as the same user, a file would be shared by
all of them, while each instance's environment is its own.
"""

from __future__ import annotations

import functools
import json
import os
import re
import urllib.parse
from dataclasses import dataclass

ENV_VAR = "NETDIAG_HTTP_AUTH"

# A path that can carry the header: unreserved characters and "/" only. No "%"
# (no encoded dot segments, double-encoding or NUL), no ";" (no "..;" matrix
# parameters) and no "\\". Report URLs never need more; anything else is sent
# without the header rather than risk a server normalising it out of the prefix.
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")


class HttpAuthConfigError(ValueError):
    """NETDIAG_HTTP_AUTH is set but malformed. The message never contains a header value or a raw prefix."""


@dataclass(frozen=True)
class Rule:
    prefix: str  # canonical https://host[:port]/path, safe to show
    host: str
    port: int
    path: str
    value: str


def _safe_path(path: str) -> bool:
    return bool(_SAFE_PATH.match(path)) and not any(seg in (".", "..") for seg in path.split("/"))


def _canonical(host: str, port: int, path: str) -> str:
    netloc = host if port == 443 else f"{host}:{port}"
    if ":" in host:  # IPv6 literal
        netloc = f"[{host}]" if port == 443 else f"[{host}]:{port}"
    return f"https://{netloc}{path}"


def _parse_prefix(prefix: str, label: str) -> tuple[str, int, str]:
    # Errors name the prefix by position only: a rejected prefix may hold a
    # secret (user info, a query token) and health_check is shown to the model.
    try:
        parts = urllib.parse.urlsplit(prefix)
        hostname = parts.hostname
        port = parts.port or 443
    except ValueError as e:  # malformed IPv6 brackets, bad port
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} is not a valid URL") from e
    if parts.scheme != "https":
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} must start with https://")
    if parts.username is not None or parts.password is not None:
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} must not contain user info")
    if parts.query or parts.fragment:
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} must not contain a query or fragment")
    if not hostname:
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} has no host")
    path = parts.path or "/"
    if not path.endswith("/"):
        raise HttpAuthConfigError(f"{ENV_VAR}: {label} must end with /")
    if not _safe_path(path):
        raise HttpAuthConfigError(
            f"{ENV_VAR}: {label} path may only use letters, digits, '.', '_', '~', '-' and '/' (no . or .. segments)"
        )
    return hostname.lower().rstrip("."), port, path


def _valid_value(value: str) -> bool:
    # Printable ASCII only: httpx encodes header values as ASCII, and an error
    # raised at send time would quote the offending character and its position.
    return bool(value) and all(0x20 <= ord(c) <= 0x7E for c in value)


@functools.lru_cache(maxsize=4)
def _parse(raw: str) -> tuple[Rule, ...]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        # e.msg and the position only; the document itself holds the secrets.
        raise HttpAuthConfigError(f"{ENV_VAR}: not valid JSON ({e.msg} at position {e.pos})") from None
    if not isinstance(data, dict):
        raise HttpAuthConfigError(f"{ENV_VAR}: must be a JSON object mapping URL prefix to header value")
    rules = []
    seen: dict[tuple[str, int, str], str] = {}
    for i, (prefix, value) in enumerate(data.items(), start=1):
        label = f"prefix #{i}"
        if not isinstance(value, str) or not _valid_value(value.strip()):
            raise HttpAuthConfigError(f"{ENV_VAR}: value for {label} must be a non-empty printable ASCII string")
        host, port, path = _parse_prefix(prefix, label)
        key = (host, port, path)
        if key in seen:
            raise HttpAuthConfigError(f"{ENV_VAR}: {label} is the same prefix as {seen[key]}")
        seen[key] = label
        rules.append(Rule(prefix=_canonical(host, port, path), host=host, port=port, path=path, value=value.strip()))
    # The most specific prefix wins when several match.
    rules.sort(key=lambda r: len(r.path), reverse=True)
    return tuple(rules)


def load_rules(environ: dict[str, str] | None = None) -> tuple[Rule, ...]:
    """Parse NETDIAG_HTTP_AUTH. Unset or empty means no rules; anything malformed raises.

    The parse is cached per distinct value, so repeated calls cost a dict lookup.
    """
    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "").strip()
    if not raw:
        return ()
    return _parse(raw)


def match(url: str, rules: tuple[Rule, ...]) -> Rule | None:
    """The rule whose prefix url falls under (longest first), or None."""
    if not rules:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
        port = parts.port or 443
    except ValueError:
        return None
    if parts.scheme != "https" or not hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = hostname.lower().rstrip(".")
    path = parts.path or "/"
    if not _safe_path(path):
        return None
    for rule in rules:
        if rule.host == host and rule.port == port and path.startswith(rule.path):
            return rule
    return None


def header_for(url: str, rules: tuple[Rule, ...]) -> dict[str, str]:
    """The Authorization header for url, or {} when no rule matches it."""
    rule = match(url, rules)
    return {"Authorization": rule.value} if rule else {}


REDACTED = "[redacted]"


def redact(body: str, headers: dict[str, str]) -> str:
    """Mask the credential that was sent in a body that echoes it back.

    Covers the full value and its credential part (after "Bearer " etc.); a
    server that transforms the value (base64, hashing) is not covered.
    """
    value = headers.get("Authorization", "")
    if not value:
        return body
    for secret in sorted({value, value.split(" ", 1)[-1]}, key=len, reverse=True):
        if len(secret) >= 8:
            body = body.replace(secret, REDACTED)
    return body


def status(environ: dict[str, str] | None = None) -> dict:
    """{"prefixes": [...], "error": str | None} for health_check. Never includes a header value."""
    try:
        rules = load_rules(environ)
    except HttpAuthConfigError as e:
        return {"prefixes": [], "error": str(e)}
    return {"prefixes": sorted(r.prefix for r in rules), "error": None}
