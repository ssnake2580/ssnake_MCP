#!/usr/bin/env python3
import json
import subprocess
import sys
import urllib.request

REPO = "ssnake2580/ssnake_MCP"
REGISTRY = "mcp/registry.json"

def github_json():
    result = subprocess.run(
        [
            "gh", "api",
            f"repos/{REPO}/contents/{REGISTRY}",
            "-H", "Accept: application/vnd.github.raw+json"
        ],
        check=True,
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def main():
    if len(sys.argv) < 2:
        print("Usage: mcp-manager.py list|status|run <MCP>")
        return 1

    action = sys.argv[1]

    if action == "list":
        for server in github_json()["servers"]:
            print(f'{server["category"]:15} {server["name"]:20} {server["status"]}')
        return 0

    if action == "status":
        return subprocess.call(["codex", "mcp", "list"])

    if action == "run":
        if len(sys.argv) != 3:
            print("Usage: mcp-manager.py run <MCP>")
            return 1

        name = sys.argv[2]
        servers = github_json()["servers"]
        server = next(
            (s for s in servers if s["name"].lower() == name.lower()),
            None
        )

        if server is None:
            print(f"Unknown MCP: {name}")
            return 1

        if server["status"] != "installed":
            print(f"{name}: MCP is not installed yet.")
            return 1

        print(f"Starting Codex with MCP: {name}")
        return subprocess.call(["codex"])

    print(f"Unknown command: {action}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
