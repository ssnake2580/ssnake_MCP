# Glama MCP safety & quality verification
# Remote MCP server at https://tools.cipherhub.cloud/cipherhub/mcp
# This Dockerfile is used exclusively by Glama for automated testing.
# It does NOT need to be deployed or added to your local environment.

FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx

# Test script: verify remote MCP server responds correctly
RUN cat > /app/test_remote.py << 'PYEOF'
"""Verify CipherHUB remote MCP server is functional."""
import sys
import httpx

ENDPOINT = "https://tools.cipherhub.cloud/cipherhub/mcp"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

def call_mcp(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    payload = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        payload["params"] = params
    resp = httpx.post(ENDPOINT, json=payload, headers=HEADERS, timeout=30.0)
    resp.raise_for_status()
    # Handle SSE streaming response
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            import json
            return json.loads(line[5:].strip())
    # Fallback: plain JSON
    return resp.json()

def main() -> int:
    errors = []

    # 1. Initialize
    try:
        result = call_mcp("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "glama-check", "version": "1.0.0"},
        })
        assert "result" in result, f"Initialize failed: {result}"
        info = result["result"].get("serverInfo", {})
        print(f"[PASS] Initialize: {info.get('name', '?')} v{info.get('version', '?')}")
    except Exception as e:
        errors.append(f"Initialize: {e}")
        print(f"[FAIL] Initialize: {e}")

    # 2. List tools
    try:
        result = call_mcp("tools/list", req_id=2)
        tools = result.get("result", {}).get("tools", [])
        print(f"[PASS] Tools listed: {len(tools)} tools")
        assert len(tools) >= 20, f"Expected >=20 tools, got {len(tools)}"
    except Exception as e:
        errors.append(f"Tools/list: {e}")
        print(f"[FAIL] Tools/list: {e}")

    # 3. List resources
    try:
        result = call_mcp("resources/list", req_id=3)
        resources = result.get("result", {}).get("resources", [])
        print(f"[PASS] Resources listed: {len(resources)} resources")
    except Exception as e:
        errors.append(f"Resources/list: {e}")
        print(f"[FAIL] Resources/list: {e}")

    # 4. Call a tool (SHA-256 hash of "Hello")
    try:
        result = call_mcp("tools/call", {
            "name": "hash_sum",
            "arguments": {
                "plain_in_hex": "48656c6c6f",
                "required_hash_modes": ["Sha256"],
            },
        }, req_id=4)
        content = result.get("result", {}).get("content", [])
        print(f"[PASS] Tool call (hash_sum): {len(content)} content items")
    except Exception as e:
        errors.append(f"Tools/call hash_sum: {e}")
        print(f"[FAIL] Tools/call hash_sum: {e}")

    if errors:
        print(f"\n{len(errors)} check(s) failed:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("\nAll checks passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
PYEOF

CMD ["python", "/app/test_remote.py"]
