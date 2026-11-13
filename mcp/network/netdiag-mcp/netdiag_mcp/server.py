"""netdiag-mcp — MCP Server tools."""

import functools
import inspect
import shutil

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError as SDKToolError
from mcp.shared.exceptions import MCPError

from netdiag_mcp import __version__, http_auth, tools
from netdiag_mcp.tools import ToolError


def _expose_errors(fn):
    """Wrap a tool so any exception reaches the model as a SDKToolError with its message.

    mcp 1.x returned the exception text for every failing tool. mcp 2.x hides it
    (the model sees only "Error executing tool <name>") unless a SDKToolError is raised.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except (SDKToolError, MCPError):
                raise
            except Exception as exc:
                raise SDKToolError(str(exc) or type(exc).__name__) from exc

    else:

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (SDKToolError, MCPError):
                raise
            except Exception as exc:
                raise SDKToolError(str(exc) or type(exc).__name__) from exc

    return wrapper


class _Server(MCPServer):
    """MCPServer whose tools report their exception messages (see _expose_errors)."""

    def tool(self, *args, **kwargs):
        register = super().tool(*args, **kwargs)

        def decorator(fn):
            register(_expose_errors(fn))
            return fn

        return decorator


mcp = _Server("netdiag-mcp", version=__version__)

# health_check probes these; missing ones degrade rather than fail outright
# so the server stays usable for whichever tools still have their binary.
_REQUIRED_BINARIES = ("dig", "ping", "mtr", "whois")


@mcp.tool()
def health_check() -> dict:
    """Service health: version, which wrapped binaries are present on PATH, and the http_get auth prefixes.

    Returns a fixed shape (status/service/version + backend fields) so a
    monitoring caller never has to branch on missing keys. status is
    "healthy" when every wrapped binary is found and NETDIAG_HTTP_AUTH (if
    set) parses, "degraded" otherwise (the affected tools fail at call time).
    http_auth lists the configured URL prefixes, never the header values.
    """

    binaries = {name: shutil.which(name) is not None for name in _REQUIRED_BINARIES}
    missing = [name for name, present in binaries.items() if not present]
    auth = http_auth.status()
    return {
        "status": "healthy" if not missing and auth["error"] is None else "degraded",
        "service": "netdiag-mcp",
        "version": __version__,
        "binaries": binaries,
        "missing": missing,
        "http_auth": auth,
    }


@mcp.tool()
def dns_lookup(hostname: str, record_type: str = "A", resolver: str | None = None, transport: str = "plain") -> str:
    """Resolve a DNS record via `dig`. record_type: A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA.

    Pass resolver to query a specific nameserver instead of the host default
    (e.g. to check whether a change has propagated to a given resolver).
    transport: "plain" (UDP/TCP 53, default), "dot" (DNS-over-TLS, 853) or
    "doh" (DNS-over-HTTPS, 443). Requires dig from BIND 9.18+; an older dig
    rejects dot/doh outright instead of silently querying over plain DNS.
    """
    try:
        return tools.dns_lookup(hostname, record_type, resolver, transport)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def dnssec_check(hostname: str, resolver: str = "1.1.1.1", transport: str = "plain") -> str:
    """Check whether a name validates DNSSEC against a known-validating resolver (AD bit).

    transport: "plain" (default), "dot" or "doh" — compare validation over
    plain DNS vs. an encrypted transport when port 53 may be intercepted.
    """
    try:
        return tools.dnssec_check(hostname, resolver, transport)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """ICMP ping a host or IP. count is clamped to 1-10."""
    try:
        return tools.ping_host(host, count)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def traceroute_path(host: str, cycles: int = 3) -> str:
    """Path/MTU-style hop report via `mtr --report` (fixed cycles, not a live run). cycles clamped 1-10."""
    try:
        return tools.traceroute_path(host, cycles)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def tcp_port_check(host: str, port: int, timeout: float = 5.0) -> str:
    """Check whether a TCP port is open (plain socket connect, no port scanning)."""
    try:
        return tools.tcp_port_check(host, port, timeout)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def http_check(url: str, timeout: float = 5.0) -> str:
    """HEAD/GET a URL and report status, redirect chain and latency."""
    try:
        return tools.http_check(url, timeout)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def http_get(url: str, timeout: float = 5.0, max_bytes: int = 262144) -> str:
    """GET a URL and return the response body (text/JSON/XML only, capped at max_bytes, hard cap 1 MiB).

    Use this to read a JSON endpoint or inspect an error page. For status/latency
    only, use http_check instead.
    """
    try:
        return tools.http_get(url, timeout, max_bytes)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def tls_cert_check(host: str, port: int = 443) -> str:
    """Fetch the TLS certificate presented on host:port and report subject/issuer/validity/SANs."""
    try:
        return tools.tls_cert_check(host, port)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain."""
    try:
        return tools.whois_lookup(domain)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def asn_lookup(target: str) -> str:
    """ASN + country-code lookup for an IP, or org info for an AS number (e.g. AS15169 or 15169).

    Via Team Cymru's whois service — no API key or GeoIP database needed.
    Takes an IP literal or AS number, not a hostname; resolve first with
    dns_lookup if you only have a name.
    """
    try:
        return tools.asn_lookup(target)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def current_time(timezone: str = "UTC") -> dict:
    """Current date, time and weekday in an IANA timezone (e.g. "Asia/Tokyo").

    Call this rather than deriving the weekday from a date yourself —
    that is calendar arithmetic and it fails silently. Returns the date,
    the 24h time, the weekday in English and Japanese, the offset, UTC and
    the epoch, so it also serves as a clock check on this server.
    """
    try:
        return tools.current_time(timezone)
    except (ValueError, ToolError) as e:
        return {"error": str(e)}
