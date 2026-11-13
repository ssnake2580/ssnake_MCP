import netdiag_mcp.server as server


def test_health_check_shape_all_present(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["service"] == "netdiag-mcp"
    assert result["missing"] == []
    assert set(result["binaries"]) == set(server._REQUIRED_BINARIES)


def test_health_check_shape_degraded_when_missing(monkeypatch):
    def fake_which(name):
        return None if name == "mtr" else "/usr/bin/x"

    monkeypatch.setattr(server.shutil, "which", fake_which)
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["missing"] == ["mtr"]


def test_dns_lookup_wraps_validation_error_as_string():
    out = server.dns_lookup("bad host name", "A")
    assert out.startswith("error:")


def test_dns_lookup_delegates_to_tools(monkeypatch):
    monkeypatch.setattr(server.tools, "dns_lookup", lambda h, r, s, t: f"{h}/{r}/{s}/{t}")
    assert server.dns_lookup("example.com", "MX", None, "doh") == "example.com/MX/None/doh"


def test_ping_host_wraps_tool_error(monkeypatch):
    def raise_tool_error(*a, **k):
        raise server.ToolError("ping not installed")

    monkeypatch.setattr(server.tools, "ping_host", raise_tool_error)
    out = server.ping_host("example.com")
    assert out == "error: ping not installed"


def test_tcp_port_check_rejects_bad_port():
    out = server.tcp_port_check("example.com", 99999)
    assert out.startswith("error:")


def test_asn_lookup_wraps_tool_error(monkeypatch):
    def raise_tool_error(*a, **k):
        raise server.ToolError("not a hostname")

    monkeypatch.setattr(server.tools, "asn_lookup", raise_tool_error)
    assert server.asn_lookup("example.com") == "error: not a hostname"


def test_asn_lookup_delegates_to_tools(monkeypatch):
    monkeypatch.setattr(server.tools, "asn_lookup", lambda t: f"asn-result for {t}")
    assert server.asn_lookup("8.8.8.8") == "asn-result for 8.8.8.8"


def test_current_time_wraps_validation_error_as_dict():
    """This tool answers with a dict, so its error must be one too."""
    out = server.current_time("../../etc/passwd")
    assert set(out) == {"error"}


def test_current_time_delegates_to_tools(monkeypatch):
    monkeypatch.setattr(server.tools, "current_time", lambda tz: {"timezone": tz})
    assert server.current_time("Asia/Tokyo") == {"timezone": "Asia/Tokyo"}
