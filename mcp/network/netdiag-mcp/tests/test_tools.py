import socket
import subprocess
import threading
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

import httpx
import pytest

from netdiag_mcp import tools
from netdiag_mcp.tools import ToolError


def test_run_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: None)
    with pytest.raises(ToolError, match="not installed"):
        tools._run("dig", ["example.com"])


def test_run_raises_on_timeout(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/dig")

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="dig", timeout=15)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ToolError, match="timed out"):
        tools._run("dig", ["example.com"])


def test_run_returns_stdout(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/dig")
    proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="192.0.2.1\n", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc)
    assert tools._run("dig", ["example.com"]) == "192.0.2.1"


def test_dns_lookup_rejects_unknown_record_type():
    with pytest.raises(ToolError, match="unsupported record type"):
        tools.dns_lookup("example.com", "BOGUS")


def test_dns_lookup_rejects_bad_hostname():
    with pytest.raises(ValueError):
        tools.dns_lookup("not a host", "A")


def test_dns_lookup_rejects_unknown_transport():
    with pytest.raises(ToolError, match="unsupported transport"):
        tools.dns_lookup("example.com", "A", transport="quic")


def test_dns_lookup_plain_transport_adds_no_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.dns_lookup("example.com", "A", transport="plain")
    assert "+tls" not in captured["args"]
    assert "+https" not in captured["args"]


@pytest.mark.parametrize("transport,flag", [("dot", "+tls"), ("doh", "+https")])
def test_dns_lookup_encrypted_transport_adds_flag(monkeypatch, transport, flag):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.dns_lookup("example.com", "A", resolver="1.1.1.1", transport=transport)
    assert flag in captured["args"]
    assert "@1.1.1.1" in captured["args"]


def test_dnssec_check_rejects_unknown_transport():
    with pytest.raises(ToolError, match="unsupported transport"):
        tools.dnssec_check("example.com", transport="quic")


@pytest.mark.parametrize("transport,flag", [("dot", "+tls"), ("doh", "+https")])
def test_dnssec_check_encrypted_transport_adds_flag(monkeypatch, transport, flag):
    captured = {}

    def fake_run(binary, args):
        captured["args"] = args
        return ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1"

    monkeypatch.setattr(tools, "_run", fake_run)
    tools.dnssec_check("example.com", transport=transport)
    assert flag in captured["args"]


def test_dnssec_check_detects_ad_flag(monkeypatch):
    fake_output = ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1\nexample.com. 300 IN A 192.0.2.1"
    monkeypatch.setattr(tools, "_run", lambda binary, args: fake_output)
    result = tools.dnssec_check("example.com")
    assert "DNSSEC validated" in result


def test_dnssec_check_reports_missing_ad_flag(monkeypatch):
    fake_output = ";; flags: qr rd ra; QUERY: 1, ANSWER: 1\nexample.com. 300 IN A 192.0.2.1"
    monkeypatch.setattr(tools, "_run", lambda binary, args: fake_output)
    result = tools.dnssec_check("example.com")
    assert "NOT validated" in result


def test_ping_host_clamps_count(monkeypatch):
    captured = {}

    def fake_run(binary, args):
        captured["args"] = args
        return "ok"

    monkeypatch.setattr(tools, "_run", fake_run)
    tools.ping_host("example.com", count=999)
    assert captured["args"][1] == "10"  # clamped to the max


def test_ping_host_sets_an_overall_deadline(monkeypatch):
    """Regression guard: without a deadline flag an unreachable target makes
    ping wait its own per-packet default for every probe (observed ~12s for
    count=2 against a black-holed address), which can exceed
    SUBPROCESS_TIMEOUT and turn a clean 100%-loss report into a hard-killed
    generic timeout error instead."""
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.ping_host("example.com", count=4)
    assert "-w" in captured["args"] or "-t" in captured["args"]


def test_ping_host_uses_ping6_for_ipv6_literal_on_macos(monkeypatch):
    """Regression guard: BSD/macOS `ping` is IPv4-only and rejects an IPv6
    literal outright ("cannot resolve ...: Unknown host") — a bare IPv6
    literal must dispatch to `ping6` there. Linux's iputils `ping` handles
    both, so this only applies off-Linux."""
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("2001:db8::1")
    assert captured["binary"] == "ping6"


def test_ping_host_uses_ping_for_ipv4_on_macos(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("192.0.2.1")
    assert captured["binary"] == "ping"


def test_ping_host_uses_ping_for_ipv6_on_linux(monkeypatch):
    """Linux's iputils ping is dual-stack — no ping6 dispatch needed there."""
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("2001:db8::1")
    assert captured["binary"] == "ping"


def test_tcp_port_check_open_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    t = threading.Thread(target=lambda: server.accept(), daemon=True)
    t.start()
    try:
        result = tools.tcp_port_check("127.0.0.1", port, timeout=2)
        assert "open" in result
    finally:
        server.close()


def test_tcp_port_check_closed_port():
    # Bind and immediately close to get a port nothing is listening on.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = tools.tcp_port_check("127.0.0.1", port, timeout=2)
    # Most platforms RST an unbound loopback port immediately (ECONNREFUSED).
    # Windows CI runners have been observed to instead let the connect()
    # attempt time out rather than refuse it right away, which
    # tcp_port_check already handles as a distinct, valid outcome (see its
    # `except TimeoutError` branch) -- accept either shape rather than
    # assuming one platform's socket behavior everywhere.
    assert "closed" in result or "unreachable" in result or "timed out" in result


def test_http_check_reports_status_and_headers(monkeypatch):
    real_client = httpx.Client

    def handler(request):
        return httpx.Response(200, headers={"server": "test-server"}, request=request)

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    result = tools.http_check("https://example.com")
    assert "200" in result
    assert "server: test-server" in result


def _mock_client(monkeypatch, handler, resolve_to="93.184.216.34"):
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(None, None, None, None, (resolve_to, port))]

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    monkeypatch.setattr(tools.socket, "getaddrinfo", fake_getaddrinfo)


def test_http_get_returns_json_body(monkeypatch):
    def handler(request):
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=b'{"ok": true}', request=request
        )

    _mock_client(monkeypatch, handler)
    result = tools.http_get("https://example.com/x.json")
    assert result.startswith("200 OK")
    assert "content-type=application/json" in result
    assert '{"ok": true}' in result


def test_http_get_truncates_at_limit(monkeypatch):
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"a" * 5000, request=request)

    _mock_client(monkeypatch, handler)
    result = tools.http_get("https://example.com/big", max_bytes=1024)
    assert "(truncated at 1024 bytes)" in result
    body = result.split("\n\n", 1)[1]
    assert len(body) == 1024


def test_http_get_refuses_binary_body(monkeypatch):
    def handler(request):
        return httpx.Response(
            200, headers={"content-type": "application/octet-stream"}, content=b"\x00\x01\x02", request=request
        )

    _mock_client(monkeypatch, handler)
    result = tools.http_get("https://example.com/blob")
    assert "body not returned" in result
    assert "\x00" not in result


def test_http_get_accepts_structured_suffix_types(monkeypatch):
    def handler(request):
        return httpx.Response(
            200, headers={"content-type": "application/problem+json"}, content=b'{"title": "x"}', request=request
        )

    _mock_client(monkeypatch, handler)
    assert '{"title": "x"}' in tools.http_get("https://example.com/p")


def test_http_get_refuses_metadata_ip_literal(monkeypatch):
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request))
    with pytest.raises(ToolError, match="blocked"):
        tools.http_get("http://169.254.169.254/latest/meta-data/")


def test_http_get_refuses_host_resolving_to_blocked_range(monkeypatch):
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request), resolve_to="127.0.0.1")
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("https://evil.example/")


def test_http_get_refuses_ipv4_mapped_loopback(monkeypatch):
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request))
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("http://[::ffff:127.0.0.1]/")
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request), resolve_to="::ffff:169.254.169.254")
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("https://evil.example/")


def test_http_get_refuses_unspecified_address(monkeypatch):
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request))
    for url in ("http://0.0.0.0/", "http://[::]/"):
        with pytest.raises(ToolError, match="blocked address"):
            tools.http_get(url)


def test_http_get_gives_up_when_budget_is_exhausted(monkeypatch):
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"x" * 100, request=request)

    _mock_client(monkeypatch, handler)
    clock = iter([0.0, 0.0, 1000.0])  # deadline set, pre-request check, first body chunk: budget gone
    monkeypatch.setattr(tools.time, "monotonic", lambda: next(clock, 1000.0))
    with pytest.raises(ToolError, match="budget"):
        tools.http_get("https://example.com/slow", timeout=1)


def test_http_get_refuses_metadata_hostname(monkeypatch):
    _mock_client(monkeypatch, lambda request: httpx.Response(200, request=request))
    with pytest.raises(ToolError, match="blocked destination"):
        tools.http_get("http://metadata.google.internal/computeMetadata/v1/")


def test_http_get_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="http"):
        tools.http_get("ftp://example.com/x")


def test_http_get_checks_redirect_target(monkeypatch):
    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"}, request=request)
        return httpx.Response(200, content=b"secret", request=request)

    _mock_client(monkeypatch, handler)
    with pytest.raises(ToolError, match="blocked"):
        tools.http_get("https://example.com/")


def test_http_get_follows_redirects_and_reports_chain(monkeypatch):
    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(301, headers={"location": "/b"}, request=request)
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"done", request=request)

    _mock_client(monkeypatch, handler)
    result = tools.http_get("https://example.com/a")
    assert "redirects: https://example.com/a -> https://example.com/b" in result
    assert result.endswith("done")


def test_http_get_stops_after_too_many_redirects(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"location": "/loop"}, request=request)

    _mock_client(monkeypatch, handler)
    with pytest.raises(ToolError, match="too many redirects"):
        tools.http_get("https://example.com/loop")


def test_http_get_honours_tiny_max_bytes(monkeypatch):
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"abcdef", request=request),
    )
    result = tools.http_get("https://example.com/", max_bytes=3)
    assert result.split("\n\n", 1)[1] == "abc"
    assert "(truncated at 3 bytes)" in result


def test_http_get_falls_back_when_charset_is_not_a_text_codec(monkeypatch):
    _mock_client(
        monkeypatch,
        lambda request: httpx.Response(
            200, headers={"content-type": "text/plain; charset=zlib_codec"}, content=b"plain", request=request
        ),
    )
    result = tools.http_get("https://example.com/")
    assert result.endswith("plain")


def test_http_get_wraps_transport_errors(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    _mock_client(monkeypatch, handler)
    with pytest.raises(ToolError, match="HTTP request failed"):
        tools.http_get("https://example.com")


def test_http_check_wraps_transport_errors(monkeypatch):
    real_client = httpx.Client

    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    with pytest.raises(ToolError, match="HTTP request failed"):
        tools.http_check("https://example.com")


def test_tls_cert_check_raises_on_connection_failure():
    # Port 1 is a reserved system port with nothing listening in CI/dev.
    with pytest.raises(ToolError):
        tools.tls_cert_check("127.0.0.1", 1)


@pytest.mark.parametrize("value", ["AS15169", "as15169", "15169"])
def test_asn_lookup_normalizes_as_number(monkeypatch, value):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.asn_lookup(value)
    assert captured["args"] == ["-h", "whois.cymru.com", " -v AS15169"]


def test_asn_lookup_passes_through_ip(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.asn_lookup("8.8.8.8")
    assert captured["args"] == ["-h", "whois.cymru.com", " -v 8.8.8.8"]


def test_asn_lookup_rejects_hostname():
    with pytest.raises(ToolError, match="not a hostname"):
        tools.asn_lookup("example.com")


def test_current_time_names_every_weekday_correctly():
    """The whole point of the tool: a weekday nobody had to calculate.

    2026-09-07 was a Monday; walk one full week from there so a
    lookup table that is rotated or short fails here rather than in a
    published report.
    """
    expected = [("Mon", "月"), ("Tue", "火"), ("Wed", "水"), ("Thu", "木"), ("Fri", "金"), ("Sat", "土"), ("Sun", "日")]
    monday = datetime(2026, 9, 7, 12, 0, tzinfo=dt_timezone.utc)
    for offset, (english, japanese) in enumerate(expected):
        got = tools.current_time("UTC", now=monday + timedelta(days=offset))
        assert (got["weekday"], got["weekday_ja"]) == (english, japanese)
        assert got["weekday_index"] == offset
        assert got["date"] == (monday + timedelta(days=offset)).strftime("%Y-%m-%d")


def test_current_time_converts_into_the_requested_zone():
    """A moment that is still the 8th in UTC is already the 9th in Tokyo."""
    got = tools.current_time("Asia/Tokyo", now=datetime(2026, 9, 8, 15, 30, tzinfo=dt_timezone.utc))
    assert got["date"] == "2026-09-09"
    assert got["time"] == "00:30"
    assert got["weekday"] == "Wed"
    assert got["weekday_ja"] == "水"
    assert got["timezone"] == "Asia/Tokyo"
    assert got["utc_offset"] == "+09:00"
    assert got["iso"] == "2026-09-09T00:30:00+09:00"
    assert got["utc"] == "2026-09-08T15:30:00Z"


def test_current_time_reads_a_naive_moment_as_utc():
    """Never as the host's local time — the answer must not depend on the server's tz."""
    naive = tools.current_time("Asia/Tokyo", now=datetime(2026, 9, 8, 15, 30))
    aware = tools.current_time("Asia/Tokyo", now=datetime(2026, 9, 8, 15, 30, tzinfo=dt_timezone.utc))
    assert naive == aware


def test_current_time_defaults_to_utc():
    got = tools.current_time(now=datetime(2026, 9, 8, 15, 30, tzinfo=dt_timezone.utc))
    assert got["timezone"] == "UTC"
    assert got["date"] == "2026-09-08"
    assert got["utc_offset"] == "+00:00"


def test_current_time_rejects_a_path_shaped_timezone():
    with pytest.raises(ValueError):
        tools.current_time("../../etc/passwd")


def test_current_time_rejects_a_well_formed_but_unknown_timezone():
    with pytest.raises(ToolError, match="unknown timezone"):
        tools.current_time("Mars/Olympus_Mons")


def test_current_time_keeps_a_sub_minute_offset_intact():
    """Pre-1900 local mean time carries seconds in its UTC offset.

    Unreachable through the MCP tool, which always reports now — but the
    offset has to come from the same rendering as ``iso`` rather than a
    fixed-width slice of ``%z`` (``+091859``), which would silently emit
    ``+09:1859``.
    """
    got = tools.current_time("Asia/Tokyo", now=datetime(1880, 1, 1, tzinfo=dt_timezone.utc))
    assert got["iso"].endswith(got["utc_offset"])
    assert got["utc_offset"].count(":") == 2, "offset truncated to ±HH:MM"
    assert datetime.fromisoformat(got["iso"]).utcoffset().total_seconds() % 60 != 0
