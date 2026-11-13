#!/usr/bin/env python3
"""
CipherHUB MCP Client Example

This script demonstrates how to call CipherHUB MCP server using Python stdlib only.
No external dependencies required.

Usage:
    python3 quickstart.py
"""

import json
import urllib.request
from typing import Any


class CipherHUBMCPClient:
    """Simple MCP client for CipherHUB using stdlib."""
    
    def __init__(self, endpoint: str = "https://tools.cipherhub.cloud/cipherhub/mcp"):
        self.endpoint = endpoint
        self.request_id = 0
    
    def call(self, method: str, params: dict | None = None) -> dict[str, Any]:
        """Make a JSON-RPC 2.0 call to the MCP server."""
        self.request_id += 1
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self.request_id
        }
        if params:
            payload["params"] = params
        
        data = json.dumps(payload).encode("utf-8")
        
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        
        if "error" in result:
            raise Exception(f"MCP Error: {result['error']}")
        
        return result.get("result", {})
    
    def list_tools(self) -> list[dict]:
        """List all available tools."""
        result = self.call("tools/list")
        return result.get("tools", [])
    
    def list_resources(self) -> list[dict]:
        """List all available resources."""
        result = self.call("resources/list")
        return result.get("resources", [])
    
    def call_tool(self, name: str, arguments: dict) -> Any:
        """Call a specific tool with arguments."""
        result = self.call("tools/call", {
            "name": name,
            "arguments": arguments
        })
        
        # Extract content from MCP response
        content = result.get("content", [])
        if content and len(content) > 0:
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return result
    
    def read_resource(self, uri: str) -> str:
        """Read a resource by URI."""
        result = self.call("resources/read", {"uri": uri})
        contents = result.get("contents", [])
        if contents:
            return contents[0].get("text", "")
        return ""


def main():
    """Demonstrate CipherHUB MCP capabilities."""
    client = CipherHUBMCPClient()
    
    print("=" * 60)
    print("CipherHUB MCP Client Demo")
    print("=" * 60)
    
    # 1. List resources
    print("\n[1] Available Resources:")
    resources = client.list_resources()
    for r in resources[:5]:
        print(f"  - {r['uri']}: {r['name']}")
    
    # 2. List tools
    # Server-side descriptions are written in Chinese; print the English
    # category tag embedded at the start of each description instead.
    print("\n[2] Available Tools (first 10):")
    tools = client.list_tools()
    for t in tools[:10]:
        desc = t.get("description", "")
        tag = desc[1:desc.find("]")] if desc.startswith("[") and "]" in desc else "uncategorized"
        print(f"  - {t['name']} [{tag}]")
    print(f"  ... and {len(tools) - 10} more tools")
    
    # 3. Compute SHA-256 hash
    print("\n[3] Compute SHA-256 Hash:")
    result = client.call_tool("hash_sum", {
        "plain_in_hex": "48656c6c6f20576f726c64",  # "Hello World" in hex
        "required_hash_modes": ["Sha256"]
    })
    print(f"  Input: 48656c6c6f20576f726c64 ('Hello World')")
    print(f"  SHA-256: {result.get('Results', {}).get('Sha256', {}).get('hash_sum_in_hex', 'N/A')}")
    
    # 4. Generate random bytes
    print("\n[4] Generate Random Bytes:")
    result = client.call_tool("generate_random_data", {
        "data_length": 16
    })
    print(f"  16 random bytes: {result.get('data_in_hex', 'N/A')}")
    
    # 5. Read the algorithms resource
    print("\n[5] Read Algorithm Catalog:")
    content = client.read_resource("cipherhub://algorithms")
    algorithms = json.loads(content)
    print(f"  Algorithm categories: {list(algorithms.keys())[:5]}...")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
