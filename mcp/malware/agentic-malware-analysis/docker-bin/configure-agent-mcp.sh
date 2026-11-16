#!/usr/bin/env bash
set -euo pipefail

AGENT_HOME="${HOME:-/home/agent}"
CLAUDE_DIR="${AGENT_HOME}/.claude"
CLAUDE_SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
CODEX_CONFIG_DIR="${AGENT_HOME}/.codex"
CODEX_CONFIG_FILE="${CODEX_CONFIG_DIR}/config.toml"
CODEX_BASE_CONFIG_TEMPLATE="${CODEX_BASE_CONFIG_TEMPLATE:-/opt/docker-config/codex-config.toml}"
CLAUDE_PROJECT_MCP="/agent/.mcp.json"

BINJA_ROOT="/agent/mcp/binary-ninja-headless-mcp"
GHIDRA_ROOT="/agent/mcp/ghidra-headless-mcp"

mkdir -p "${CLAUDE_DIR}"
mkdir -p "${CODEX_CONFIG_DIR}"

python3 - "${CLAUDE_SETTINGS_FILE}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = {}
if path.exists():
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        data = {}

trusted = list(dict.fromkeys((data.get("trustedDirectories") or []) + ["/agent", "/home/agent"]))
data["trustedDirectories"] = trusted
path.write_text(json.dumps(data))
PY

write_codex_base_config() {
  if [ ! -f "${CODEX_BASE_CONFIG_TEMPLATE}" ]; then
    echo "error: missing Codex config template: ${CODEX_BASE_CONFIG_TEMPLATE}" >&2
    exit 1
  fi

  install -m 0644 "${CODEX_BASE_CONFIG_TEMPLATE}" "${CODEX_CONFIG_FILE}"
}

# Ensure Binary Ninja Python API is installed for the current user.
# The Dockerfile runs install_api.py as root during build, but the container
# runs as the "agent" user whose site-packages may not have the .pth file.
if [ -f /opt/binaryninja/scripts/install_api.py ]; then
  if ! python3 -c "import binaryninja" 2>/dev/null; then
    echo "[mcp] installing Binary Ninja Python API for $(whoami)"
    python3 /opt/binaryninja/scripts/install_api.py
  fi
fi

# Detect which MCP backend is available
mcp_name=""
mcp_command=""
mcp_args=""
mcp_env=""

if [ -f /opt/binaryninja/scripts/install_api.py ] && [ -f "${BINJA_ROOT}/binary_ninja_headless_mcp.py" ]; then
  mcp_name="binary_ninja_headless_mcp"
  mcp_command="python3"
  mcp_args="[\"${BINJA_ROOT}/binary_ninja_headless_mcp.py\"]"
  mcp_env="{}"
elif [ -f "${GHIDRA_ROOT}/ghidra_headless_mcp.py" ] || { [ -f "${GHIDRA_ROOT}/pyproject.toml" ] && [ -d "${GHIDRA_ROOT}/ghidra_headless_mcp" ]; }; then
  mcp_name="ghidra_headless_mcp"
  mcp_command="python3"
  if [ -f "${GHIDRA_ROOT}/ghidra_headless_mcp.py" ]; then
    mcp_args="[\"${GHIDRA_ROOT}/ghidra_headless_mcp.py\"]"
  else
    mcp_args="[\"${GHIDRA_ROOT}/ghidra_headless_mcp.py\"]"
  fi
  ghidra_install_dir="${GHIDRA_INSTALL_DIR:-}"
  if [ -z "${ghidra_install_dir}" ] && [ -d /usr/share/ghidra ]; then
    ghidra_install_dir="/usr/share/ghidra"
  fi
  if [ -n "${ghidra_install_dir}" ]; then
    mcp_env="{\"GHIDRA_INSTALL_DIR\": \"${ghidra_install_dir}\"}"
  else
    mcp_env="{}"
  fi
else
  echo "warning: no MCP backend (Binary Ninja or Ghidra) found, skipping MCP configuration" >&2
  # Write empty MCP configs
  printf '%s\n' '{"mcpServers":{}}' > "${CLAUDE_PROJECT_MCP}"
  write_codex_base_config
  exit 0
fi

# Write Claude Code .mcp.json
cat > "${CLAUDE_PROJECT_MCP}" <<EOF
{
  "mcpServers": {
    "${mcp_name}": {
      "type": "stdio",
      "command": "${mcp_command}",
      "args": ${mcp_args},
      "env": ${mcp_env}
    }
  }
}
EOF

# Write Codex config with env vars for MCP server
codex_env_section=""
if [ "${mcp_env}" != "{}" ] && [ -n "${mcp_env}" ]; then
  codex_env_section=$(python3 -c "
import json, sys
env = json.loads(sys.argv[1])
for k, v in env.items():
    print(f'{k} = \"{v}\"')
" "${mcp_env}")
fi

write_codex_base_config
cat >> "${CODEX_CONFIG_FILE}" <<EOF

[mcp_servers.${mcp_name}]
command = "${mcp_command}"
args = ${mcp_args}
EOF
if [ -n "${codex_env_section}" ]; then
cat >> "${CODEX_CONFIG_FILE}" <<EOF

[mcp_servers.${mcp_name}.env]
${codex_env_section}
EOF
fi
