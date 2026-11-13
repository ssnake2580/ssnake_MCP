#!/usr/bin/env python3
import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = "ssnake2580/ssnake_MCP"
REGISTRY = "mcp/registry.json"

def registry():
    result = subprocess.run(
        [
            "gh", "api",
            f"repos/{REPO}/contents/{REGISTRY}",
            "-H", "Accept: application/vnd.github.raw+json"
        ],
        check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)["servers"]

def codex_config():
    path = Path.home() / ".codex/config.toml"
    with path.open("rb") as f:
        return tomllib.load(f)

def main():
    if len(sys.argv) < 2:
        print("Usage: list | status | run <MCP> [MCP...]")
        return 1

    action = sys.argv[1]

    if action == "list":
        for s in registry():
            print(f'{s["category"]:15} {s["name"]:20} {s["status"]}')
        return 0

    if action == "status":
        return subprocess.call(["codex", "mcp", "list"])

    if action == "run":
        if len(sys.argv) < 3:
            print("Usage: run <MCP> [MCP...]")
            return 1

        servers = registry()
        configured = codex_config().get("mcp_servers", {})
        selected = set()

        for name in sys.argv[2:]:
            server = next(
                (s for s in servers
                 if s["name"].casefold() == name.casefold()),
                None
            )
            if server is None:
                print(f"Unknown MCP: {name}")
                return 1

            if server["status"] != "installed":
                print(f"Not installed: {name}")
                return 1

            key = server["name"].lower().replace(" ", "-")

            if key not in configured:
                print(f"Not configured in Codex: {key}")
                return 1

            selected.add(key)

        args = ["codex"]

        for name in configured:
            enabled = "true" if name in selected else "false"
            args.extend([
                "-c", f"mcp_servers.{name}.enabled={enabled}"
            ])

        print("Selected MCP:", ", ".join(sorted(selected)), flush=True)
        return subprocess.call(args)

    print(f"Unknown command: {action}")
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
