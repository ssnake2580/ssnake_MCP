# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Configuration loader for snmp-mcp.

Resolves host connection settings from (in priority order):

  1. Environment variables (`SNMP_MCP_<HOST>_<FIELD>`)
  2. TOML config file (default `~/.config/snmp-mcp/config.toml`,
     honours `$XDG_CONFIG_HOME`, overridable via `SNMP_MCP_CONFIG`)
  3. Defaults baked into this module

See DESIGN.md §6 for the schema.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

_ADDRESS_ALIASES = ("address", "ip", "host")
_AUTH_PASS_ALIASES = ("auth_pass", "auth_password")
_PRIV_PASS_ALIASES = ("priv_pass", "priv_password")

_VALID_VERSIONS = {"v1", "v2c", "v3"}
_VALID_AUTH_PROTOS = {"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
_VALID_PRIV_PROTOS = {"DES", "3DES", "AES128", "AES192", "AES256"}


@dataclass
class HostConfig:
    """Resolved connection settings for one SNMP target."""

    name: str
    address: str
    version: str = "v2c"
    port: int = 161
    timeout: float = 3.0
    retries: int = 2
    # v1/v2c
    community: str | None = None
    # v3
    user: str | None = None
    auth_proto: str | None = None
    auth_pass: str | None = None
    priv_proto: str | None = None
    priv_pass: str | None = None
    context: str = ""
    verify_engine_id: bool = True

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"HostConfig(name={self.name!r}, address={self.address!r}, "
            f"version={self.version!r}, port={self.port}, "
            f"community={'***' if self.community else None}, "
            f"user={self.user!r}, "
            f"auth_pass={'***' if self.auth_pass else None}, "
            f"priv_pass={'***' if self.priv_pass else None})"
        )

    def validate(self) -> None:
        """Raise ConfigError if the resolved config is internally inconsistent."""
        if not self.address:
            raise ConfigError(
                f"host {self.name!r} missing required field 'address'",
                host=self.name,
            )
        if self.version not in _VALID_VERSIONS:
            raise ConfigError(
                f"host {self.name!r} has invalid version {self.version!r} "
                f"(expected one of {sorted(_VALID_VERSIONS)})",
                host=self.name,
            )
        if self.version in ("v1", "v2c"):
            if not self.community:
                raise ConfigError(
                    f"host {self.name!r} ({self.version}) missing required field 'community'",
                    host=self.name,
                )
        else:  # v3
            if not self.user:
                raise ConfigError(
                    f"host {self.name!r} (v3) missing required field 'user'",
                    host=self.name,
                )
            if self.auth_proto is not None and self.auth_proto not in _VALID_AUTH_PROTOS:
                raise ConfigError(
                    f"host {self.name!r} (v3) has invalid auth_proto "
                    f"{self.auth_proto!r} (expected one of "
                    f"{sorted(_VALID_AUTH_PROTOS)})",
                    host=self.name,
                )
            if self.priv_proto is not None and self.priv_proto not in _VALID_PRIV_PROTOS:
                raise ConfigError(
                    f"host {self.name!r} (v3) has invalid priv_proto "
                    f"{self.priv_proto!r} (expected one of "
                    f"{sorted(_VALID_PRIV_PROTOS)})",
                    host=self.name,
                )
            if self.priv_proto and not self.auth_proto:
                raise ConfigError(
                    f"host {self.name!r} (v3) has priv_proto set without "
                    f"auth_proto — priv requires auth",
                    host=self.name,
                )


@dataclass
class _Defaults:
    """Defaults applied to all hosts unless overridden."""

    version: str = "v2c"
    port: int = 161
    timeout: float = 3.0
    retries: int = 2
    verify_engine_id: bool = True


@dataclass
class Config:
    """Top-level configuration: defaults + per-host table."""

    defaults: _Defaults = field(default_factory=_Defaults)
    hosts: dict[str, HostConfig] = field(default_factory=dict)

    def get_host(self, name: str) -> HostConfig:
        """Return resolved HostConfig for `name`, layering env vars over file."""
        env_overlay = _collect_env_for_host(name)
        file_host = self.hosts.get(name)
        if file_host is None and not env_overlay:
            raise ConfigError(
                f"unknown host {name!r}: not in config file and no env vars set",
                host=name,
            )
        merged: dict[str, Any] = {}
        if file_host is not None:
            merged = {
                "address": file_host.address,
                "version": file_host.version,
                "port": file_host.port,
                "timeout": file_host.timeout,
                "retries": file_host.retries,
                "community": file_host.community,
                "user": file_host.user,
                "auth_proto": file_host.auth_proto,
                "auth_pass": file_host.auth_pass,
                "priv_proto": file_host.priv_proto,
                "priv_pass": file_host.priv_pass,
                "context": file_host.context,
                "verify_engine_id": file_host.verify_engine_id,
            }
        merged.update(env_overlay)
        merged.setdefault("version", self.defaults.version)
        merged.setdefault("port", self.defaults.port)
        merged.setdefault("timeout", self.defaults.timeout)
        merged.setdefault("retries", self.defaults.retries)
        merged.setdefault("verify_engine_id", self.defaults.verify_engine_id)
        merged.setdefault("context", "")
        host = HostConfig(name=name, address=merged.pop("address", ""), **merged)
        host.validate()
        return host


def default_config_path() -> Path:
    """Return the default config-file path, honouring XDG_CONFIG_HOME."""
    override = os.environ.get("SNMP_MCP_CONFIG")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "snmp-mcp" / "config.toml"


def load_config(path: Path | str | None = None) -> Config:
    """Load and parse the TOML config file (or return defaults if missing)."""
    if path is None:
        path = default_config_path()
    path = Path(path).expanduser()
    if not path.exists():
        return Config()
    try:
        with path.open("rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"failed to read config {path}: {exc}") from exc
    return _parse_config(raw)


def _parse_config(raw: dict[str, Any]) -> Config:
    cfg = Config()
    defaults_raw = raw.get("defaults", {})
    if not isinstance(defaults_raw, dict):
        raise ConfigError("[defaults] must be a table")
    if "version" in defaults_raw:
        cfg.defaults.version = str(defaults_raw["version"])
    if "port" in defaults_raw:
        cfg.defaults.port = int(defaults_raw["port"])
    if "timeout" in defaults_raw:
        cfg.defaults.timeout = float(defaults_raw["timeout"])
    if "retries" in defaults_raw:
        cfg.defaults.retries = int(defaults_raw["retries"])
    if "verify_engine_id" in defaults_raw:
        cfg.defaults.verify_engine_id = bool(defaults_raw["verify_engine_id"])

    hosts_raw = raw.get("hosts", {})
    if not isinstance(hosts_raw, dict):
        raise ConfigError("[hosts] must be a table")
    for name, host_raw in hosts_raw.items():
        if not isinstance(host_raw, dict):
            raise ConfigError(f"[hosts.{name}] must be a table")
        cfg.hosts[name] = _parse_host(name, host_raw, cfg.defaults)
    return cfg


def _parse_host(name: str, raw: dict[str, Any], defaults: _Defaults) -> HostConfig:
    address = _first_alias(raw, _ADDRESS_ALIASES) or ""
    auth_pass = _first_alias(raw, _AUTH_PASS_ALIASES)
    priv_pass = _first_alias(raw, _PRIV_PASS_ALIASES)
    return HostConfig(
        name=name,
        address=address,
        version=str(raw.get("version", defaults.version)),
        port=int(raw.get("port", defaults.port)),
        timeout=float(raw.get("timeout", defaults.timeout)),
        retries=int(raw.get("retries", defaults.retries)),
        community=raw.get("community"),
        user=raw.get("user"),
        auth_proto=raw.get("auth_proto"),
        auth_pass=auth_pass,
        priv_proto=raw.get("priv_proto"),
        priv_pass=priv_pass,
        context=str(raw.get("context", "")),
        verify_engine_id=bool(raw.get("verify_engine_id", defaults.verify_engine_id)),
    )


def _first_alias(raw: dict[str, Any], aliases: tuple[str, ...]) -> str | None:
    for key in aliases:
        if key in raw:
            return str(raw[key])
    return None


# --- Env var overlay ---------------------------------------------------------


def _env_prefix(host: str) -> str:
    """Normalize a host name to its env-var prefix.

    `switch-core` → `SNMP_MCP_SWITCH_CORE_`
    `printer.example.com` → `SNMP_MCP_PRINTER_EXAMPLE_COM_`
    """
    sanitized = "".join(c if c.isalnum() else "_" for c in host).upper()
    return f"SNMP_MCP_{sanitized}_"


_ENV_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "address": ("ADDRESS", "IP", "HOST"),
    "version": ("VERSION",),
    "port": ("PORT",),
    "timeout": ("TIMEOUT",),
    "retries": ("RETRIES",),
    "community": ("COMMUNITY",),
    "user": ("USER",),
    "auth_proto": ("AUTH_PROTO",),
    "auth_pass": ("AUTH_PASS", "AUTH_PASSWORD"),
    "priv_proto": ("PRIV_PROTO",),
    "priv_pass": ("PRIV_PASS", "PRIV_PASSWORD"),
    "context": ("CONTEXT",),
    "verify_engine_id": ("VERIFY_ENGINE_ID",),
}

_BOOL_FIELDS = {"verify_engine_id"}
_INT_FIELDS = {"port", "retries"}
_FLOAT_FIELDS = {"timeout"}


def _collect_env_for_host(host: str) -> dict[str, Any]:
    """Collect env-var overrides for `host`, returning a kwargs dict."""
    prefix = _env_prefix(host)
    out: dict[str, Any] = {}
    for field_name, aliases in _ENV_FIELD_ALIASES.items():
        for alias in aliases:
            key = prefix + alias
            val = os.environ.get(key)
            if val is None or val == "":
                continue
            out[field_name] = _coerce(field_name, val)
            break
    return out


def _coerce(field_name: str, raw: str) -> Any:
    if field_name in _BOOL_FIELDS:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if field_name in _INT_FIELDS:
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"env var for {field_name!r} not an int: {raw!r}") from exc
    if field_name in _FLOAT_FIELDS:
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigError(f"env var for {field_name!r} not a number: {raw!r}") from exc
    return raw
