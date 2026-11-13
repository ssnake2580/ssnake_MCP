#!/usr/bin/env python3
import base64
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



def save_verification(name, protocol, tool_count):
    from datetime import datetime, timezone

    url = f"repos/{REPO}/contents/{REGISTRY}"
    result = subprocess.run(
        ["gh", "api", url + "?ref=main"],
        capture_output=True, text=True, check=True
    )
    metadata = json.loads(result.stdout)
    data = json.loads(base64.b64decode(metadata["content"]))

    server = find(data["servers"], name)
    if server is None:
        raise ValueError(f"Registry entry not found: {name}")

    server["verification"] = {
        "status": "passed",
        "protocol_version": protocol,
        "tool_count": tool_count,
        "verified_at": datetime.now(timezone.utc).isoformat()
    }

    encoded = base64.b64encode(
        (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    ).decode()

    subprocess.run(
        [
            "gh", "api", "--method", "PUT", url,
            "-f", f"message=verify: update {name} MCP status",
            "-f", f"content={encoded}",
            "-f", f"sha={metadata['sha']}",
            "--silent"
        ],
        check=True
    )
    print("[OK] Verification saved to GitHub Registry")


def verify_mcp(name, save=False):
    import os
    import select
    import time

    name = name.lower()
    current = configured()

    if name in current:
        entry = current[name]
        if "command" not in entry:
            print("Only stdio MCP servers are supported.")
            return 1
        command = [entry["command"], *entry.get("args", [])]
        env = os.environ.copy()
        env.update(entry.get("env", {}))
    elif name == "filesystem":
        directory = str(Path.home() / "MCP")
        if not Path(directory).is_dir():
            print("Filesystem directory not found:", directory)
            return 1
        command = [
            "npx", "-y",
            "@modelcontextprotocol/server-filesystem@2.3.0",
            "--read-only", directory
        ]
        env = os.environ.copy()
    elif name == "playwright":
        command = [
            "npx", "-y", "@playwright/mcp@latest",
            "--headless"
        ]
        env = os.environ.copy()
    else:
        print("No verification recipe:", name)
        return 1

    print("Verifying MCP:", name, flush=True)
    print("Starting server...", flush=True)

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        bufsize=0
    )

    buffer = bytearray()
    deadline = time.monotonic() + 90

    def send(message):
        data = json.dumps(message, separators=(",", ":"))
        proc.stdin.write((data + "\n").encode())
        proc.stdin.flush()

    def receive(request_id):
        nonlocal buffer

        while time.monotonic() < deadline:
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer = bytearray(rest)

                try:
                    message = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue

                if message.get("id") == request_id:
                    return message

            if proc.poll() is not None:
                raise RuntimeError(
                    f"MCP server exited early: {proc.returncode}"
                )

            remaining = max(0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [proc.stdout], [], [], min(remaining, 1)
            )

            if readable:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError("MCP server closed stdout")
                buffer.extend(chunk)

        raise TimeoutError("MCP verification timed out (90s)")

    try:
        send({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "ssnake-mcp-verifier",
                    "version": "1.0"
                }
            }
        })

        initialized = receive(1)
        if "error" in initialized:
            raise RuntimeError(str(initialized["error"]))

        result = initialized.get("result", {})
        if not result.get("protocolVersion"):
            raise RuntimeError("Invalid initialize response")

        print("Initialize: OK")
        print("Protocol:", result["protocolVersion"])

        send({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })

        send({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })

        response = receive(2)
        if "error" in response:
            raise RuntimeError(str(response["error"]))

        tools = response.get("result", {}).get("tools")
        if not isinstance(tools, list):
            raise RuntimeError("Invalid tools/list response")

        print("Tools:", len(tools))
        if save:
            save_verification(name, result["protocolVersion"], len(tools))
        print("[OK] MCP protocol verification successful")
        return 0

    except (OSError, RuntimeError, TimeoutError) as error:
        print("[FAIL]", error)
        return 1

    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()


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

    if action == "verify":
        if len(args) not in (2, 3) or (
            len(args) == 3 and args[2] != "--save"
        ):
            print("Usage: mcp verify NAME [--save]")
            return 1
        return verify_mcp(args[1], save="--save" in args[2:])

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
