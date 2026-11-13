import pytest

from netdiag_mcp.validate import clamp, validate_port, validate_target


@pytest.mark.parametrize(
    "value",
    ["example.com", "sub.example.co.jp", "192.0.2.1", "2001:db8::1", "a.b", "localhost"],
)
def test_validate_target_accepts_valid_input(value):
    assert validate_target(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "   ", "has space.com", "evil.com; rm -rf /", "a" * 254, "bad\nname.com"],
)
def test_validate_target_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        validate_target(value)


def test_validate_target_strips_surrounding_whitespace():
    assert validate_target("  example.com  ") == "example.com"


@pytest.mark.parametrize("value", [1, 80, 443, 65535])
def test_validate_port_accepts_valid_range(value):
    assert validate_port(value) == value


@pytest.mark.parametrize("value", [0, -1, 65536, 100000])
def test_validate_port_rejects_out_of_range(value):
    with pytest.raises(ValueError):
        validate_port(value)


def test_clamp_bounds_both_directions():
    assert clamp(-5, 1, 10) == 1
    assert clamp(50, 1, 10) == 10
    assert clamp(5, 1, 10) == 5
