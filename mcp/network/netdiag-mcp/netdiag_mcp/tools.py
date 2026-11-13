"""Wrappers around external diagnostic binaries and Python's own socket/ssl/httpx stack.

Every external-binary call uses an argv list (never shell=True), so no
argument can break out into shell syntax regardless of what the caller
passes — validate.py's job is bounding *size*, not escaping.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
from datetime import datetime
from datetime import timezone as _dt_timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from netdiag_mcp import http_auth
from netdiag_mcp.validate import clamp, validate_port, validate_target, validate_timezone

DEFAULT_TIMEOUT = 5.0
SUBPROCESS_TIMEOUT = 15.0

DNS_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "CAA"}

# dig flag for each transport. "plain" adds nothing (classic UDP/TCP port 53).
# +tls/+https require dig from BIND 9.18+; an older dig rejects the flag
# outright ("Invalid option", exit 1) rather than silently falling back to
# plain DNS, so a stale `dig` fails loudly here instead of giving a false
# sense of having checked over an encrypted transport.
_DNS_TRANSPORT_FLAGS = {"plain": None, "dot": "+tls", "doh": "+https"}

# Indexed by datetime.weekday() — 0 is Monday.
_WEEKDAYS_EN = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_WEEKDAYS_JA = ("月", "火", "水", "木", "金", "土", "日")


class ToolError(Exception):
    """A tool could not run at all (missing binary, timeout, bad input)."""


def _run(binary: str, args: list[str]) -> str:
    if shutil.which(binary) is None:
        raise ToolError(f"{binary} is not installed on this host")
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise ToolError(f"{binary} timed out after {SUBPROCESS_TIMEOUT:g}s") from e
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    if proc.returncode != 0 and not out:
        raise ToolError(err or f"{binary} exited {proc.returncode} with no output")
    return out if not err else f"{out}\n[stderr] {err}" if out else err


def _transport_flag(transport: str) -> str | None:
    key = transport.strip().lower()
    if key not in _DNS_TRANSPORT_FLAGS:
        raise ToolError(f"unsupported transport {transport!r}; use one of {sorted(_DNS_TRANSPORT_FLAGS)}")
    return _DNS_TRANSPORT_FLAGS[key]


def dns_lookup(hostname: str, record_type: str = "A", resolver: str | None = None, transport: str = "plain") -> str:
    """transport: "plain" (UDP/TCP 53, default), "dot" (DNS-over-TLS, 853) or "doh" (DNS-over-HTTPS, 443)."""
    target = validate_target(hostname)
    rtype = record_type.strip().upper()
    if rtype not in DNS_RECORD_TYPES:
        raise ToolError(f"unsupported record type {record_type!r}; use one of {sorted(DNS_RECORD_TYPES)}")
    flag = _transport_flag(transport)
    args = []
    if resolver:
        args.append(f"@{validate_target(resolver)}")
    if flag:
        args.append(flag)
    args += [target, rtype, "+noall", "+answer", "+stats"]
    return _run("dig", args)


def dnssec_check(hostname: str, resolver: str = "1.1.1.1", transport: str = "plain") -> str:
    """Query a validating resolver and report whether the AD (Authenticated Data) bit is set.

    A bare `dig` reply with an RRSIG present does NOT mean DNSSEC validated
    — only a resolver that itself validates and sets the AD flag proves
    that. This deliberately targets a known-validating public resolver
    rather than trusting whatever the host's default resolver is.

    transport lets you compare validation over plain DNS vs. DoT/DoH — useful
    when a network intercepts/spoofs port 53 but leaves 443/853 alone.
    """
    target = validate_target(hostname)
    res = validate_target(resolver)
    flag = _transport_flag(transport)
    args = [f"@{res}"]
    if flag:
        args.append(flag)
    args += [target, "+dnssec", "+noall", "+comment", "+answer"]
    out = _run("dig", args)
    ad_set = "flags:" in out and " ad" in out.split("flags:", 1)[1].split(";", 1)[0]
    verdict = "DNSSEC validated (AD bit set)" if ad_set else "DNSSEC NOT validated (AD bit absent)"
    return f"{verdict}\n\n{out}"


def _is_ipv6_literal(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 6
    except ValueError:
        return False  # hostname — let ping's own resolver pick a family


def ping_host(host: str, count: int = 4) -> str:
    """ping with an explicit overall deadline where the binary supports one.

    Without a deadline, an unreachable target makes `ping` wait its own
    per-packet default for every probe (observed ~12s for count=2 against a
    black-holed address), which can exceed SUBPROCESS_TIMEOUT and get
    hard-killed into a generic "timed out" ToolError instead of ping's own
    clean 100%-loss report. iputils (Linux, the deploy target) takes an
    overall deadline via `-w`; BSD/macOS `ping` takes one via `-t`.

    On Linux a single `ping` binary handles both families. BSD/macOS's
    `ping` is IPv4-only and rejects an IPv6 literal outright ("cannot
    resolve ...: Unknown host") — this dispatches to `ping6` there instead,
    which has no overall-deadline flag at all (its `-t` means something
    unrelated: an ICMPv6 Node Information query type), so an unreachable
    IPv6 target on macOS falls back to the SUBPROCESS_TIMEOUT backstop and
    a generic timeout error rather than a clean loss report — a narrow gap
    limited to local macOS testing, since Linux never takes this branch.
    An IPv6-only *hostname* on macOS still isn't handled (that would need a
    pre-resolve this tool deliberately doesn't do), but a bare IPv6 literal
    now works on both platforms.
    """
    target = validate_target(host)
    n = clamp(count, 1, 10)
    deadline = clamp(n * 2, 4, 10)
    is_linux = platform.system() == "Linux"
    binary = "ping" if is_linux or not _is_ipv6_literal(target) else "ping6"
    args = ["-c", str(n)]
    if binary != "ping6":
        args += ["-w" if is_linux else "-t", str(deadline)]
    args.append(target)
    return _run(binary, args)


def traceroute_path(host: str, cycles: int = 3) -> str:
    """mtr in report mode — a fixed number of cycles, not a live/continuous run."""
    target = validate_target(host)
    n = clamp(cycles, 1, 10)
    return _run("mtr", ["--report", "--report-cycles", str(n), "--no-dns", target])


def whois_lookup(domain: str) -> str:
    target = validate_target(domain)
    return _run("whois", [target])


_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)


def asn_lookup(target: str) -> str:
    """ASN + country-code lookup for an IP, or org info for an AS number, via
    Team Cymru's whois service (whois.cymru.com) — no API key or GeoIP
    database needed, reuses the `whois` binary already required by
    whois_lookup. Accepts an IP literal or an AS number (`AS15169` or
    `15169`), not a hostname — Cymru's service does prefix/ASN lookups, not
    DNS resolution, so resolve a hostname with dns_lookup first.
    """
    stripped = target.strip()
    m = _ASN_RE.match(stripped)
    if m:
        query = f"AS{m.group(1)}"
    else:
        try:
            ipaddress.ip_address(stripped)
        except ValueError as e:
            raise ToolError(
                f"asn_lookup takes an IP address or AS number (e.g. AS15169 or 15169), "
                f"not a hostname: {target!r}. Resolve it first with dns_lookup."
            ) from e
        query = validate_target(stripped)
    # The leading space before "-v" is a documented whois.cymru.com quirk:
    # their server parses flags out of the raw query string itself (the
    # standard whois protocol has no argv-style options), and drops the
    # -v verbose header line without it.
    return _run("whois", ["-h", "whois.cymru.com", f" -v {query}"])


def tcp_port_check(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Native TCP connect probe — no `nc` dependency, no shell involved at all."""
    target = validate_target(host)
    p = validate_port(port)
    t = clamp(timeout, 1, 15)
    start = time.monotonic()
    try:
        with socket.create_connection((target, p), timeout=t):
            elapsed_ms = (time.monotonic() - start) * 1000
            return f"{target}:{p} open ({elapsed_ms:.1f}ms)"
    except TimeoutError:
        return f"{target}:{p} timed out after {t:g}s"
    except (ConnectionRefusedError, OSError) as e:
        return f"{target}:{p} closed/unreachable: {e}"


def http_check(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """HEAD (falling back to GET) via httpx — reports status, redirect chain and latency."""
    t = clamp(timeout, 1, 15)
    try:
        with httpx.Client(follow_redirects=True, timeout=t) as client:
            start = time.monotonic()
            resp = client.head(url)
            if resp.status_code == 405:
                resp = client.get(url)
            elapsed_ms = (time.monotonic() - start) * 1000
    except httpx.HTTPError as e:
        raise ToolError(f"HTTP request failed: {e}") from e
    lines = [f"{resp.status_code} {resp.reason_phrase}  {elapsed_ms:.0f}ms  final_url={resp.url}"]
    if resp.history:
        chain = " -> ".join(str(r.url) for r in [*resp.history, resp])
        lines.append(f"redirects: {chain}")
    for header in ("server", "content-type", "content-length"):
        if header in resp.headers:
            lines.append(f"{header}: {resp.headers[header]}")
    return "\n".join(lines)


HTTP_GET_DEFAULT_BYTES = 256 * 1024
HTTP_GET_MAX_BYTES = 1024 * 1024
HTTP_GET_MAX_REDIRECTS = 5
HTTP_GET_BUDGET_FACTOR = 3  # whole-call wall clock = timeout * this, across redirects and the body read
_TEXTUAL_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-ndjson",
    "application/yaml",
    "application/x-yaml",
)
# Destinations http_get refuses to fetch. Loopback and link-local cover the cloud
# instance-metadata services (169.254.169.254 on AWS/GCP/Azure, fd00:ec2::254 on
# AWS IPv6) that hand out credentials to anything on the box; the hostnames are
# the well-known aliases for the same endpoints.
_BLOCKED_NETS = tuple(
    ipaddress.ip_network(n) for n in ("127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fd00:ec2::254/128")
)
_BLOCKED_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal", "instance-data"})


def _is_textual(content_type: str) -> bool:
    ctype = content_type.split(";", 1)[0].strip().lower()
    if ctype.startswith(_TEXTUAL_TYPES):
        return True
    return ctype.endswith("+json") or ctype.endswith("+xml")


def _check_destination(url: str) -> str:
    """Validate scheme/host and refuse loopback, link-local and metadata endpoints.

    Resolves the hostname and checks every address, so a name that points at a
    blocked range is refused too. The check happens before the connection is
    opened; a record that changes between the check and the connect is not
    covered, which is acceptable for a diagnostics tool.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("url must start with http:// or https://")
    if not parts.hostname:
        raise ValueError("url has no host")
    host = validate_target(parts.hostname)
    if host.lower().rstrip(".") in _BLOCKED_HOSTS:
        raise ToolError(f"refusing to fetch {host}: blocked destination")
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise ToolError(f"cannot resolve {host}: {e}") from e
        addrs = {ipaddress.ip_address(info[4][0]) for info in infos}
    for addr in addrs:
        # ::ffff:127.0.0.1 is IPv6 to ipaddress but reaches the IPv4 loopback;
        # compare the embedded IPv4 address. 0.0.0.0 / :: connect to localhost
        # on Linux and belong to no listed range, so refuse them by name.
        real = getattr(addr, "ipv4_mapped", None) or addr
        if real.is_unspecified or any(real in net for net in _BLOCKED_NETS):
            raise ToolError(f"refusing to fetch {host}: resolves to blocked address {addr}")
    return url


def http_get(url: str, timeout: float = DEFAULT_TIMEOUT, max_bytes: int = HTTP_GET_DEFAULT_BYTES) -> str:
    """GET a URL via httpx and return the decoded body (textual types only, size-capped).

    Redirects are followed by hand, one hop at a time, so every destination is
    checked against the blocklist and no intermediate body is ever read.

    ``timeout`` is httpx's per-operation (connect/read) timeout; a server that
    trickles one byte per read would never trip it, so the whole call is also
    bounded by ``timeout * HTTP_GET_BUDGET_FACTOR`` of wall clock.

    When NETDIAG_HTTP_AUTH is set (see http_auth), each hop is sent with the
    Authorization header of the prefix it falls under, decided per hop so a
    redirect to another origin drops it. ``auth=applied`` on the status line
    says the final hop carried one; the value is never returned.
    """
    try:
        rules = http_auth.load_rules()
    except http_auth.HttpAuthConfigError as e:
        raise ToolError(str(e)) from None
    t = clamp(timeout, 1, 15)
    limit = clamp(max_bytes, 1, HTTP_GET_MAX_BYTES)
    budget = t * HTTP_GET_BUDGET_FACTOR
    deadline = time.monotonic() + budget
    current = _check_destination(url.strip())
    hops: list[str] = []
    authed = False
    prev_rule: http_auth.Rule | None = None

    def check_deadline() -> None:
        if time.monotonic() > deadline:
            raise ToolError(f"http_get exceeded its {budget:g}s budget")

    try:
        with httpx.Client(follow_redirects=False, timeout=t) as client:
            for _ in range(HTTP_GET_MAX_REDIRECTS + 1):
                check_deadline()
                rule = http_auth.match(current, rules)
                # A cookie set while a credential was attached must not follow a
                # redirect out of that prefix (even into another prefix with the
                # same value); ordinary redirects keep their cookies.
                if prev_rule is not None and rule != prev_rule:
                    client.cookies.clear()
                prev_rule = rule
                authed = rule is not None
                headers = {"Authorization": rule.value} if rule else {}
                with client.stream("GET", current, headers=headers) as resp:
                    if resp.is_redirect and "location" in resp.headers:
                        hops.append(current)
                        current = _check_destination(str(resp.url.join(resp.headers["location"])))
                        continue
                    ctype = resp.headers.get("content-type", "")
                    status = f"{resp.status_code} {resp.reason_phrase}"
                    final_url = str(resp.url)
                    encoding = resp.encoding or "utf-8"
                    buf = bytearray()
                    if _is_textual(ctype):
                        for chunk in resp.iter_bytes(chunk_size=65536):
                            check_deadline()
                            room = limit + 1 - len(buf)
                            buf.extend(chunk[:room])
                            if len(buf) > limit:
                                break
                    break
            else:
                raise ToolError(f"too many redirects (>{HTTP_GET_MAX_REDIRECTS})")
    except httpx.HTTPError as e:
        raise ToolError(f"HTTP request failed: {e}") from e
    head = f"{status}  final_url={final_url}  content-type={ctype or '(none)'}"
    if authed:
        head += "  auth=applied"
    if hops:
        head += "\nredirects: " + " -> ".join([*hops, final_url])
    if not _is_textual(ctype):
        return head + "\nbody not returned: non-textual content type"
    truncated = len(buf) > limit
    raw = bytes(buf[:limit])
    try:
        body = raw.decode(encoding, errors="replace")
    except LookupError:
        body = raw.decode("utf-8", errors="replace")
    head += f"  bytes={len(raw)}"
    if truncated:
        head += f"  (truncated at {limit} bytes)"
    if authed:
        body = http_auth.redact(body, {"Authorization": prev_rule.value} if prev_rule else {})
    return head + "\n\n" + body


def tls_cert_check(host: str, port: int = 443) -> str:
    """Native ssl/socket TLS handshake — reports the peer certificate, not raw openssl s_client text."""
    target = validate_target(host)
    p = validate_port(port)
    ctx = ssl.create_default_context()
    # create_default_context() already excludes TLS 1.0/1.1 on modern Python,
    # but CodeQL's py/insecure-protocol flags the absence of an explicit
    # minimum here regardless — set it explicitly so the guarantee doesn't
    # depend on the runtime's ssl module defaults.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((target, p), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as e:
        return f"TLS handshake failed certificate verification: {e}"
    except (TimeoutError, OSError) as e:
        raise ToolError(f"could not connect to {target}:{p}: {e}") from e
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    lines = [
        f"subject: {subject.get('commonName', '?')}",
        f"issuer: {issuer.get('commonName', '?')}",
        f"validity: {cert.get('notBefore')} -> {cert.get('notAfter')}",
        f"cipher: {cipher[0]} {cipher[1]}" if cipher else "cipher: ?",
    ]
    if sans:
        lines.append(f"subjectAltName: {', '.join(sans)}")
    return "\n".join(lines)


def current_time(timezone: str = "UTC", now: datetime | None = None) -> dict:
    """Current date, time and weekday in the requested IANA timezone.

    The weekday is the reason this exists. Working it out from a date is
    calendar arithmetic, and a caller that gets it wrong gets it wrong
    silently, so it is returned as data instead. ``weekday_ja`` carries the
    same value in Japanese for callers rendering Japanese output.

    Doubles as a clock check: a host whose time has drifted breaks TLS
    validity windows, Kerberos and log correlation, so ``utc`` and ``epoch``
    are reported next to the local view.

    Args:
        timezone: IANA zone name, e.g. "Asia/Tokyo". Defaults to UTC.
        now: fixed moment to report instead of the current one.
            # injectable for tests
    """
    zone = validate_timezone(timezone)
    try:
        tz = ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise ToolError(f"unknown timezone {zone!r}: {e}") from e
    moment = now if now is not None else datetime.now(_dt_timezone.utc)
    if moment.tzinfo is None:
        # A naive moment is read as UTC, never as the host's local time, so
        # the answer does not depend on how the server happens to be set.
        moment = moment.replace(tzinfo=_dt_timezone.utc)
    local = moment.astimezone(tz)
    index = local.weekday()
    iso = local.isoformat(timespec="seconds")
    return {
        "timezone": zone,
        "date": local.strftime("%Y-%m-%d"),
        "time": local.strftime("%H:%M"),
        "weekday": _WEEKDAYS_EN[index],
        "weekday_ja": _WEEKDAYS_JA[index],
        "weekday_index": index,
        "iso": iso,
        # Taken from the ISO string rather than rebuilt from %z: isoformat
        # renders ±HH:MM, and ±HH:MM:SS for the sub-minute offsets that
        # pre-1900 local mean time carries, whereas %z is ±HHMM(SS) and
        # would need its own width special-case. timespec="seconds" fixes
        # the datetime half at 19 characters, so the rest is the offset.
        "utc_offset": iso[19:],
        "utc": moment.astimezone(_dt_timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "epoch": int(moment.timestamp()),
    }
