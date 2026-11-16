from mcp_scheduler.json_parser import safe_parse_json

def test_safe_parse_json_valid():
    obj, err = safe_parse_json('{"foo": 1}')
    assert obj == {"foo": 1}
    assert err is None

def test_safe_parse_json_invalid():
    obj, err = safe_parse_json('{foo: 1}')
    assert obj is None
    assert err is not None
