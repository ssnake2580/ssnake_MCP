from __future__ import annotations

from scapy_mcp.config.settings import ScapySettings, get_settings


def test_defaults_match_spec() -> None:
    s = ScapySettings(_env_file=None)
    assert s.http_port == 3056
    assert s.capture_packet_cap == 10_000
    assert s.capture_duration_cap_seconds == 60
    assert s.capture_default_bpf_filter is None
    assert s.capture_executor_workers == 2
    assert s.transmit_enabled is False  # closed position
    assert s.transmit_allow_l3_cidrs == []
    assert s.transmit_allow_l2 is False
    assert s.transmit_allow_broadcast is False
    assert s.transmit_max_pps == 10
    assert s.transmit_max_per_session == 100
    assert s.transmit_max_probe_targets == 16
    assert s.pcap_read_max_bytes == 52_428_800


def test_transmit_enabled_master_switch_defaults_false() -> None:
    s = ScapySettings(_env_file=None)
    assert s.transmit_enabled is False  # fresh install cannot emit a frame


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


def test_env_var_override_works() -> None:
    s = ScapySettings(_env_file=None, transmit_max_pps=50)
    assert s.transmit_max_pps == 50
