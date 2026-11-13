#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = "ssnake2580/ssnake_MCP"
REGISTRY = "mcp/registry.json"
STATE = Path.home() / ".config/ssnake-mcp/managed.json"

def call(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def registry():
    result = call(
        ["gh", "api", f"repos/{REPO}/contents/{REGISTRY}",
         "-H", "Accept: application/vnd.github.raw+json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)["servers"]

def configured():
    with (Path.home() / ".codex/config.toml").open("rb") as f:
        return tomllib.load(f).get("mcp_servers", {})

def managed():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return []

def save_managed(names):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(names, indent=2) + "\n")
    os.chmod(STATE, 0o600)

def find(servers, name):
    return next((s for s in servers
                 if s["name"].casefold() == name.casefold()), None)

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: mcp list|status|info|install|cleanup|run")
        return 1

    action = args[0]

    if action == "status":
        return subprocess.call(["codex", "mcp", "list"])

    if action == "cleanup":
        names = managed()
        if not names:
            print("No manager-installed MCPs to clean up.")
            return 0

        current = configured()
        remaining = list(names)

        for name in names:
            if name in current:
                print(f"Removing manager-installed MCP: {name}")
                call(["codex", "mcp", "remove", name])
            remaining.remove(name)
            save_managed(remaining)

        print("Cleanup complete. REA was preserved.")
        return 0

    servers = registry()

    if action == "list":
        current = configured()
        for s in servers:
            name = s["name"]
            key = name.lower().replace(" ", "-")
            status = "configured" if key in current else s["status"]
            print(f'{s["category"]:15} {name:20} {status}')
        return 0

    if action == "info":
        if len(args) < 2:
            print("Usage: mcp info NAME")
            return 1
        s = find(servers, " ".join(args[1:]))
        if not s:
            print("Unknown MCP")
            return 1
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0

    if action == "install":
        if len(args) != 2:
            print("Usage: mcp install filesystem|playwright")
            return 1

        name = args[1].lower()
        current = configured()

        if name in current:
            print(f"{name} is already configured; no changes made.")
            return 0

        if name == "filesystem":
            directory = str(Path.home() / "MCP")
            if not Path(directory).is_dir():
                print(f"Directory not found: {directory}")
                return 1
            command = [
                "codex", "mcp", "add", "filesystem", "--",
                "npx", "-y",
                "@modelcontextprotocol/server-filesystem@2.3.0",
                "--read-only", directory
            ]
        elif name == "playwright":
            command = [
                "codex", "mcp", "add", "playwright", "--",
                "npx", "-y", "@playwright/mcp@latest",
                "--headless"
            ]
        else:
            print(f"Install recipe not available: {name}")
            return 1

        print("Registering:", name, flush=True)
        call(command)

        names = managed()
        if name not in names:
            names.append(name)
            save_managed(names)

        print(f"[OK] {name} registered in Codex")
        return 0

    if action == "run":
        if len(args) < 2:
            print("Usage: mcp run NAME [NAME...]")
            return 1

        current = configured()
        selected = set()

        for name in args[1:]:
            s = find(servers, name)
            if not s:
                print(f"Unknown MCP: {name}")
                return 1

            key = name.lower().replace(" ", "-")
            if key not in current:
                print(f"Not configured in Codex: {key}")
                return 1

            selected.add(key)

        cmd = ["codex"]
        for name in current:
            if not all(c.isascii() and
                       (c.isalnum() or c in "_-") for c in name):
                print(f"Unsupported MCP config name: {name}")
                return 1
            value = "true" if name in selected else "false"
            cmd += ["-c", f"mcp_servers.{name}.enabled={value}"]

        print("Selected MCP:", ", ".join(sorted(selected)), flush=True)
        return subprocess.call(cmd)

    print("Unknown command:", action)
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
