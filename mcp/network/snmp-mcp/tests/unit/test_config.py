# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Unit tests for config.py — TOML loader + env-var overlay + validation."""

from __future__ import annotations

import pytest

from snmp_mcp.config import Config, load_config
from snmp_mcp.errors import ConfigError


def _write_toml(tmp_path, contents: str):
    p = tmp_path / "config.toml"
    p.write_text(contents, encoding="utf-8")
    return p


def test_load_minimal_v2c_config(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.switch-core]
        address = "10.0.0.10"
        version = "v2c"
        community = "public"
        """,
    )
    cfg = load_config(path)
    host = cfg.get_host("switch-core")
    assert host.address == "10.0.0.10"
    assert host.version == "v2c"
    assert host.community == "public"
    assert host.port == 161
    assert host.timeout == 3.0
    assert host.retries == 2


def test_alias_keys_for_address(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        ip = "10.0.0.5"
        version = "v2c"
        community = "x"
        """,
    )
    cfg = load_config(path)
    assert cfg.get_host("a").address == "10.0.0.5"


def test_defaults_table_applied(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [defaults]
        port = 1610
        timeout = 5.0
        retries = 4

        [hosts.a]
        address = "10.0.0.10"
        version = "v2c"
        community = "x"
        """,
    )
    host = load_config(path).get_host("a")
    assert host.port == 1610
    assert host.timeout == 5.0
    assert host.retries == 4


def test_env_var_overrides_file(tmp_path, monkeypatch) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.switch-core]
        address = "10.0.0.10"
        version = "v2c"
        community = "from_file"
        """,
    )
    monkeypatch.setenv("SNMP_MCP_SWITCH_CORE_COMMUNITY", "from_env")
    monkeypatch.setenv("SNMP_MCP_SWITCH_CORE_TIMEOUT", "10.0")
    host = load_config(path).get_host("switch-core")
    assert host.community == "from_env"
    assert host.timeout == 10.0


def test_env_only_host_with_no_file(monkeypatch) -> None:
    monkeypatch.setenv("SNMP_MCP_CRS312_ADDRESS", "10.10.3.130")
    monkeypatch.setenv("SNMP_MCP_CRS312_VERSION", "v2c")
    monkeypatch.setenv("SNMP_MCP_CRS312_COMMUNITY", "secret")
    cfg = Config()
    host = cfg.get_host("crs312")
    assert host.address == "10.10.3.130"
    assert host.community == "secret"


def test_unknown_host_raises_config_error() -> None:
    cfg = Config()
    with pytest.raises(ConfigError):
        cfg.get_host("nope")


def test_missing_address_raises(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        version = "v2c"
        community = "x"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("a")


def test_v2c_missing_community_raises(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        address = "10.0.0.1"
        version = "v2c"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("a")


def test_v3_missing_user_raises(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        address = "10.0.0.1"
        version = "v3"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("a")


def test_v3_priv_without_auth_raises(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        address = "10.0.0.1"
        version = "v3"
        user = "m"
        priv_proto = "AES128"
        priv_pass = "x"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("a")


def test_invalid_auth_proto_raises(tmp_path) -> None:
    path = _write_toml(
        tmp_path,
        """
        [hosts.a]
        address = "10.0.0.1"
        version = "v3"
        user = "m"
        auth_proto = "ROT13"
        auth_pass = "x"
        """,
    )
    cfg = load_config(path)
    with pytest.raises(ConfigError):
        cfg.get_host("a")


def test_invalid_version_raises(monkeypatch) -> None:
    monkeypatch.setenv("SNMP_MCP_X_ADDRESS", "10.0.0.1")
    monkeypatch.setenv("SNMP_MCP_X_VERSION", "v9000")
    monkeypatch.setenv("SNMP_MCP_X_COMMUNITY", "x")
    cfg = Config()
    with pytest.raises(ConfigError):
        cfg.get_host("x")


def test_missing_file_returns_empty_config(tmp_path) -> None:
    cfg = load_config(tmp_path / "no_such_file.toml")
    assert isinstance(cfg, Config)
    assert cfg.hosts == {}


def test_hostname_with_dots_in_env(monkeypatch) -> None:
    monkeypatch.setenv("SNMP_MCP_PRINTER_EXAMPLE_COM_ADDRESS", "192.0.2.5")
    monkeypatch.setenv("SNMP_MCP_PRINTER_EXAMPLE_COM_VERSION", "v2c")
    monkeypatch.setenv("SNMP_MCP_PRINTER_EXAMPLE_COM_COMMUNITY", "p")
    cfg = Config()
    host = cfg.get_host("printer.example.com")
    assert host.address == "192.0.2.5"


def test_auth_pass_alias(monkeypatch) -> None:
    monkeypatch.setenv("SNMP_MCP_X_ADDRESS", "10.0.0.1")
    monkeypatch.setenv("SNMP_MCP_X_VERSION", "v3")
    monkeypatch.setenv("SNMP_MCP_X_USER", "m")
    monkeypatch.setenv("SNMP_MCP_X_AUTH_PROTO", "SHA")
    monkeypatch.setenv("SNMP_MCP_X_AUTH_PASSWORD", "via_alias")
    cfg = Config()
    host = cfg.get_host("x")
    assert host.auth_pass == "via_alias"


def test_invalid_int_env_var_raises(monkeypatch) -> None:
    monkeypatch.setenv("SNMP_MCP_X_ADDRESS", "10.0.0.1")
    monkeypatch.setenv("SNMP_MCP_X_VERSION", "v2c")
    monkeypatch.setenv("SNMP_MCP_X_COMMUNITY", "x")
    monkeypatch.setenv("SNMP_MCP_X_PORT", "not_a_number")
    cfg = Config()
    with pytest.raises(ConfigError):
        cfg.get_host("x")


def test_default_config_path_honours_xdg(monkeypatch, tmp_path) -> None:
    from snmp_mcp.config import default_config_path

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("SNMP_MCP_CONFIG", raising=False)
    assert default_config_path() == tmp_path / "snmp-mcp" / "config.toml"


def test_default_config_path_uses_override(monkeypatch, tmp_path) -> None:
    from snmp_mcp.config import default_config_path

    custom = tmp_path / "custom.toml"
    monkeypatch.setenv("SNMP_MCP_CONFIG", str(custom))
    assert default_config_path() == custom


def test_malformed_toml_raises(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("this is = = not valid [[[", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)
