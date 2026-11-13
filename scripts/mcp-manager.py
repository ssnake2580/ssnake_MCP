#!/usr/bin/env python3
import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = "ssnake2580/ssnake_MCP"
REGISTRY = "mcp/registry.json"

def get_registry():
    result = subprocess.run(
        ["gh", "api",
         f"repos/{REPO}/contents/{REGISTRY}",
         "-H", "Accept: application/vnd.github.raw+json"],
        check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)["servers"]

def get_config():
    path = Path.home() / ".codex/config.toml"
    with path.open("rb") as f:
        return tomllib.load(f)

def find_server(servers, name):
    return next(
        (s for s in servers
         if s["name"].casefold() == name.casefold()),
        None
    )

def main():
    if len(sys.argv) < 2:
        print("Usage: mcp list|status|info NAME|run NAME [NAME...]")
        return 1

    action = sys.argv[1]

    if action == "status":
        return subprocess.call(["codex", "mcp", "list"])

    if action not in ("list", "info", "run"):
        print("Unknown command:", action)
        return 1

    servers = get_registry()

    if action == "list":
        for s in servers:
            print(f'{s["category"]:15} {s["name"]:20} {s["status"]}')
        return 0

    if len(sys.argv) < 3:
        print(f"Usage: mcp {action} NAME")
        return 1

    if action == "info":
        server = find_server(servers, " ".join(sys.argv[2:]))
        if server is None:
            print("MCP not found")
            return 1
        print(json.dumps(server, indent=2, ensure_ascii=False))
        return 0

    configured = get_config().get("mcp_servers", {})
    selected = set()

    for name in sys.argv[2:]:
        server = find_server(servers, name)

        if server is None:
            print(f"Unknown MCP: {name}")
            return 1

        if server["status"] != "installed":
            print(f"Not installed: {name}")
            return 1

        execution = server.get("execution") or {}
        key = execution.get("codex_name") or (
            server["name"].lower().replace(" ", "-")
        )

        if key not in configured:
            print(f"Not configured in Codex: {key}")
            return 1

        selected.add(key)

    args = ["codex"]

    for name in configured:
        enabled = "true" if name in selected else "false"
        # JSON quoting safely handles TOML keys with punctuation.
        key = json.dumps(name)
        args.extend([
            "-c", f"mcp_servers.{key}.enabled={enabled}"
        ])

    print("Selected MCP:", ", ".join(sorted(selected)), flush=True)
    return subprocess.call(args)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
