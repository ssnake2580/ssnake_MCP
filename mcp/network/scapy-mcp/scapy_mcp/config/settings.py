"""ScapySettings — every key/default from spec §13.4.

``pcap_write_dir`` defaults to ``<runtime_dir>/pcap-staging`` per spec §13.4,
where ``runtime_dir = tempfile.gettempdir()``. This avoids embedding a
project-root absolute path into the default and keeps production installs
writeable under ``/tmp/scapy_mcp/pcap-staging`` without creating repo-local
``var/`` directories.

Every ``transmit_*`` default is the closed position: a fresh install cannot
emit a frame.
"""

from __future__ import annotations

import tempfile
from functools import lru_cache
from pathlib import Path

from mcp_common.auth.config import AuthConfig
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# scapy_mcp/config/settings.py -> config -> scapy_mcp -> <repo root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class ScapySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCAPY_MCP_",
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Server
    http_port: int | None = 3056
    tool_profile: str = "full"
    log_level: str = "INFO"

    # Auth (Task 14). Optional — ``Runtime`` only constructs the
    # BearerTokenMiddleware when ``auth.enabled`` is True. Configured via
    # ``settings/scapy-mcp.yaml`` (``auth: {enabled: true, ...}``) or via
    # ``SCAPY_MCP_AUTH__*`` env vars (pydantic-settings nested delimiter
    # is ``__``). Default is None (auth disabled) so a fresh install boots
    # without auth — matching the pre-Task-14 behavior.
    auth: AuthConfig | None = None

    # Capture
    default_iface: str | None = None
    capture_packet_cap: int = 10_000
    capture_duration_cap_seconds: int = 60
    capture_default_bpf_filter: str | None = None
    capture_executor_workers: int = 2

    # PCAP — default `<runtime_dir>/pcap-staging` (spec §13.4)
    pcap_write_dir: Path = Field(
        default_factory=lambda: Path(tempfile.gettempdir()) / "scapy_mcp" / "pcap-staging",
    )
    pcap_read_max_bytes: int = 52_428_800

    # Transmit — all defaults are the closed position
    transmit_enabled: bool = False
    transmit_allow_l3_cidrs: list[str] = Field(default_factory=list)
    transmit_allow_l2: bool = False
    transmit_allow_broadcast: bool = False
    transmit_max_pps: int = 10
    transmit_max_per_session: int = 100
    transmit_max_probe_targets: int = 16


@lru_cache(maxsize=1)
def get_settings() -> ScapySettings:
    return ScapySettings()
