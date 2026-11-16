# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate or check the shared Claude setup block and plugin version."""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- client-contract:claude-code:start -->"
END = "<!-- client-contract:claude-code:end -->"


def generated_files(root: Path = ROOT) -> dict[Path, bytes]:
    canonical = root / "src/vt_mcp/client_contracts.json"
    data = json.loads(canonical.read_text("utf-8"))["claude_code"]
    block = (
        START + "\n```sh\n" + "\n".join(data["install_commands"]) + "\n```\n\n"
        f"Requires Claude Code **{data['minimum_version']} or later**. "
        "The plugin needs no separate Node.js installation and runs no hooks or bundled scripts. "
        f"The plugin includes `{data['server_url']}`.\n" + END
    )
    result = {}
    plugin_path = root / "plugins/claude-code/.claude-plugin/plugin.json"
    plugin = json.loads(plugin_path.read_text("utf-8"))
    plugin["version"] = data["plugin_version"]
    result[plugin_path] = (json.dumps(plugin, indent=2) + "\n").encode()
    for name in ["README.md", "docs/claude-code.md", "plugins/claude-code/README.md"]:
        path = root / name
        text = path.read_text("utf-8")
        if text.count(START) != 1 or text.count(END) != 1:
            raise ValueError(f"Expected one client contract block in {name}")
        before, rest = text.split(START)
        _, after = rest.split(END)
        if data["manual_http_command"] not in before + after:
            raise ValueError(f"Manual HTTP alternative differs from the contract in {name}")
        result[path] = (before + block + after).encode()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    changed = []
    for path, content in generated_files().items():
        if path.exists() and path.read_bytes() == content:
            continue
        changed.append(str(path.relative_to(ROOT)))
        if not args.check:
            path.write_bytes(content)
    if args.check and changed:
        raise SystemExit("Regenerate client contract files: " + ", ".join(changed))


if __name__ == "__main__":
    main()
