import json
import os
import subprocess
import sys

import httpx
import pytest

import netdiag_mcp.server as server
from netdiag_mcp import http_auth, tools

SECRET = "Bearer s3cr3t-token-value"
PREFIX = "https://reports.example.ac.jp/daily/"


def _env(mapping):
    return {http_auth.ENV_VAR: json.dumps(mapping)}


def _rules(mapping=None):
    return http_auth.load_rules(_env(mapping or {PREFIX: SECRET}))


# --- parsing ---


def test_unset_or_empty_means_no_rules():
    assert http_auth.load_rules({}) == ()
    assert http_auth.load_rules({http_auth.ENV_VAR: "  "}) == ()


@pytest.mark.parametrize(
    "raw",
    [
        "not json " + SECRET,
        json.dumps([PREFIX, SECRET]),
        json.dumps({PREFIX: ""}),
        json.dumps({PREFIX: 42}),
        json.dumps({PREFIX: SECRET + "\r\nX-Injected: 1"}),
        json.dumps({"http://reports.example.ac.jp/daily/": SECRET}),
        json.dumps({"https://reports.example.ac.jp/daily": SECRET}),
        json.dumps({"https://user@reports.example.ac.jp/daily/": SECRET}),
        json.dumps({"https://reports.example.ac.jp/daily/?a=1": SECRET}),
        json.dumps({"https://reports.example.ac.jp/a/../daily/": SECRET}),
        json.dumps({"https:///daily/": SECRET}),
        json.dumps({"https://[broken/daily/": SECRET}),
        json.dumps({"https://[xyz]/daily/": SECRET}),
        json.dumps({PREFIX: "Bearer secあret"}),
        json.dumps({PREFIX: "Bearer s3cr3t\x01"}),
        json.dumps({"https://reports.example.ac.jp/da%20ily/": SECRET}),
        json.dumps(
            {"https://Reports.example.ac.jp/daily/": SECRET, "https://reports.example.ac.jp:443/daily/": SECRET}
        ),
    ],
)
def test_malformed_config_raises_without_echoing_the_value(raw):
    with pytest.raises(http_auth.HttpAuthConfigError) as exc:
        http_auth.load_rules({http_auth.ENV_VAR: raw})
    assert "s3cr3t" not in str(exc.value)


@pytest.mark.parametrize(
    "prefix",
    ["https://u:s3cr3t@reports.example.ac.jp/daily/", "https://reports.example.ac.jp/daily/?token=s3cr3t"],
)
def test_rejected_prefix_is_named_by_position_not_text(prefix):
    with pytest.raises(http_auth.HttpAuthConfigError) as exc:
        http_auth.load_rules(_env({PREFIX: SECRET, prefix: SECRET}))
    assert "prefix #2" in str(exc.value)
    assert "s3cr3t" not in str(exc.value)


def test_duplicate_prefixes_are_rejected():
    with pytest.raises(http_auth.HttpAuthConfigError) as exc:
        http_auth.load_rules(
            _env(
                {
                    "https://REPORTS.example.ac.jp./daily/": "Bearer a",
                    "https://reports.example.ac.jp:443/daily/": "Bearer b",
                }
            )
        )
    assert "prefix #2 is the same prefix as prefix #1" in str(exc.value)


def test_prefixes_are_reported_in_canonical_form():
    rules = _rules({"https://REPORTS.example.ac.jp:443/daily/": SECRET, "https://[2001:db8::1]:8443/x/": SECRET})
    assert sorted(r.prefix for r in rules) == ["https://[2001:db8::1]:8443/x/", PREFIX]


# --- matching ---


@pytest.mark.parametrize(
    "url",
    [
        "https://reports.example.ac.jp/daily/2026-10-12.json",
        "https://REPORTS.example.ac.jp/daily/x.json",
        "https://reports.example.ac.jp./daily/x.json",
        "https://reports.example.ac.jp:443/daily/x.json",
        "https://reports.example.ac.jp/daily/",
    ],
)
def test_matching_urls_get_the_header(url):
    assert http_auth.header_for(url, _rules()) == {"Authorization": SECRET}


@pytest.mark.parametrize(
    "url",
    [
        "http://reports.example.ac.jp/daily/x.json",  # never over plain http
        "https://reports.example.ac.jp/dailyX/x.json",  # segment boundary
        "https://reports.example.ac.jp/other/x.json",
        "https://reports.example.ac.jp:8443/daily/x.json",  # other port
        "https://reports.example.ac.jp.evil.example/daily/x.json",  # suffix trick
        "https://reports.example.ac.jp@evil.example/daily/x.json",  # userinfo trick
        "https://user:pw@reports.example.ac.jp/daily/x.json",  # userinfo on the right host
        "https://reports.example.ac.jp/daily/../other/x.json",
        "https://reports.example.ac.jp/daily/%2e%2e/other/x.json",
        "https://evil.example/daily/x.json",
        "https://[broken/daily/x.json",
        "https://reports.example.ac.jp/daily/..;/admin",
        "https://reports.example.ac.jp/daily/%252e%252e/admin",
        "https://reports.example.ac.jp/daily/..%00/admin",
        "https://reports.example.ac.jp/daily/a;b/x.json",
        "https://reports.example.ac.jp/daily/a\\..\\x",
    ],
)
def test_non_matching_urls_get_nothing(url):
    assert http_auth.header_for(url, _rules()) == {}


def test_longest_prefix_wins():
    rules = _rules({"https://reports.example.ac.jp/": "Bearer broad", PREFIX: "Bearer narrow"})
    assert http_auth.header_for(PREFIX + "x.json", rules) == {"Authorization": "Bearer narrow"}
    assert http_auth.header_for("https://reports.example.ac.jp/x.json", rules) == {"Authorization": "Bearer broad"}


def test_ip_literal_prefix():
    rules = _rules({"https://192.0.2.10/daily/": SECRET})
    assert http_auth.header_for("https://192.0.2.10/daily/x.json", rules) == {"Authorization": SECRET}
    assert http_auth.header_for("https://192.0.2.11/daily/x.json", rules) == {}


# --- http_get ---


def _mock_client(monkeypatch, handler, resolve_to="93.184.216.34"):
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(None, None, None, None, (resolve_to, port))]

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    monkeypatch.setattr(tools.socket, "getaddrinfo", fake_getaddrinfo)


def test_http_get_sends_header_only_to_matching_url(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))
    seen = {}

    def handler(request):
        seen[str(request.url)] = request.headers.get("authorization")
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}", request=request)

    _mock_client(monkeypatch, handler)
    out = tools.http_get(PREFIX + "a.json")
    assert "auth=applied" in out
    assert "s3cr3t" not in out
    out = tools.http_get("https://reports.example.ac.jp/other.json")
    assert "auth=applied" not in out
    assert seen == {PREFIX + "a.json": SECRET, "https://reports.example.ac.jp/other.json": None}


def test_http_get_drops_header_when_redirected_to_another_origin(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("authorization")))
        if request.url.host == "reports.example.ac.jp":
            return httpx.Response(302, headers={"location": "https://evil.example/steal"}, request=request)
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok", request=request)

    _mock_client(monkeypatch, handler)
    out = tools.http_get(PREFIX + "a.json")
    assert seen == [("reports.example.ac.jp", SECRET), ("evil.example", None)]
    assert "auth=applied" not in out
    assert "s3cr3t" not in out


def test_http_get_keeps_header_on_same_prefix_redirect(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("authorization")))
        if request.url.path.endswith("/latest.json"):
            return httpx.Response(302, headers={"location": "/daily/2026-10-12.json"}, request=request)
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}", request=request)

    _mock_client(monkeypatch, handler)
    out = tools.http_get(PREFIX + "latest.json")
    assert seen == [("/daily/latest.json", SECRET), ("/daily/2026-10-12.json", SECRET)]
    assert "auth=applied" in out


def test_http_get_keeps_cookies_on_ordinary_redirects(monkeypatch):
    monkeypatch.delenv(http_auth.ENV_VAR, raising=False)
    seen = []

    def handler(request):
        seen.append(request.headers.get("cookie"))
        if request.url.path == "/login":
            return httpx.Response(
                302, headers={"location": "/page", "set-cookie": "SESSION=x; Path=/"}, request=request
            )
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok", request=request)

    _mock_client(monkeypatch, handler)
    tools.http_get("https://example.com/login")
    assert seen == [None, "SESSION=x"]


def test_http_get_clears_cookies_between_prefixes_with_the_same_value(monkeypatch):
    other = "https://reports.example.ac.jp/other/"
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET, other: SECRET}))
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("cookie")))
        if request.url.path.startswith("/daily/"):
            return httpx.Response(
                302, headers={"location": other + "page", "set-cookie": "SESSION=private; Path=/"}, request=request
            )
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok", request=request)

    _mock_client(monkeypatch, handler)
    tools.http_get(PREFIX + "start")
    assert seen == [("/daily/start", None), ("/other/page", None)]


def test_http_get_redacts_an_echoed_credential(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))

    def handler(request):
        body = json.dumps({"headers": {"Authorization": request.headers.get("authorization")}})
        return httpx.Response(200, headers={"content-type": "application/json"}, content=body.encode(), request=request)

    _mock_client(monkeypatch, handler)
    out = tools.http_get(PREFIX + "headers")
    assert "s3cr3t" not in out
    assert "[redacted]" in out


def test_redact_masks_the_token_part_too():
    assert http_auth.redact("token=s3cr3t-token-value", {"Authorization": SECRET}) == "token=[redacted]"
    assert http_auth.redact("nothing here", {}) == "nothing here"


def test_http_get_does_not_carry_cookies_across_hops(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))
    seen = []

    def handler(request):
        seen.append((str(request.url), request.headers.get("cookie"), request.headers.get("authorization")))
        if request.url.path.startswith("/daily/"):
            return httpx.Response(
                302,
                headers={"location": "https://reports.example.ac.jp/other", "set-cookie": "SESSION=s3cr3t; Path=/"},
                request=request,
            )
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok", request=request)

    _mock_client(monkeypatch, handler)
    tools.http_get(PREFIX + "a.json")
    assert seen[1] == ("https://reports.example.ac.jp/other", None, None)


def test_http_get_fails_loudly_on_malformed_config(monkeypatch):
    monkeypatch.setenv(http_auth.ENV_VAR, '{"http://reports.example.ac.jp/daily/": "' + SECRET + '"}')
    with pytest.raises(tools.ToolError) as exc:
        tools.http_get(PREFIX + "a.json")
    assert "s3cr3t" not in str(exc.value)
    out = server.http_get(PREFIX + "a.json")
    assert out.startswith("error:")
    assert "s3cr3t" not in out


# --- health_check / CLI ---


def test_health_check_lists_prefixes_not_values(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({PREFIX: SECRET}))
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["http_auth"] == {"prefixes": [PREFIX], "error": None}
    assert "s3cr3t" not in json.dumps(result)


def test_health_check_degraded_on_malformed_config(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    monkeypatch.setenv(http_auth.ENV_VAR, "{" + SECRET)
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["http_auth"]["prefixes"] == []
    assert result["http_auth"]["error"]
    assert "s3cr3t" not in json.dumps(result)


def test_health_check_degraded_on_unparsable_prefix(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    monkeypatch.setenv(http_auth.ENV_VAR, json.dumps({"https://[broken/daily/": SECRET}))
    result = server.health_check()
    assert result["status"] == "degraded"
    assert "not a valid URL" in result["http_auth"]["error"]
    assert "s3cr3t" not in json.dumps(result)


def test_health_check_unset(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    monkeypatch.delenv(http_auth.ENV_VAR, raising=False)
    assert server.health_check()["http_auth"] == {"prefixes": [], "error": None}


def test_cli_check_reports_malformed_config_from_the_environment():
    """End to end: the variable reaches the process the way a unit's EnvironmentFile delivers it."""
    # Inherit the environment (Windows needs SYSTEMROOT for sockets) and override the variable.
    env = {**os.environ, http_auth.ENV_VAR: '{"http://reports.example.ac.jp/daily/": "' + SECRET + '"}'}
    proc = subprocess.run(
        [sys.executable, "-m", "netdiag_mcp", "--check"], capture_output=True, text=True, env=env, timeout=60
    )
    assert proc.returncode == 2
    assert "must start with https://" in proc.stderr
    assert "s3cr3t" not in proc.stdout + proc.stderr
