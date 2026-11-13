#!/bin/bash
#
# CipherHUB MCP Server - cURL Examples
#
# This script demonstrates how to call the CipherHUB MCP server using curl.
#

set -e

MCP_ENDPOINT="https://tools.cipherhub.cloud/cipherhub/mcp"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}CipherHUB MCP Server - cURL Examples${NC}"
echo -e "${CYAN}========================================${NC}"

# 1. List available tools
echo -e "\n${GREEN}[1] List Available Tools${NC}"
echo "Request: tools/list"
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 -c "
import sys, json
data = json.load(sys.stdin)
tools = data.get('result', {}).get('tools', [])
print(f'Found {len(tools)} tools:')
for t in tools[:5]:
    print(f\"  - {t['name']}\")
print(f'  ... and {len(tools) - 5} more')
"

# 2. List available resources
echo -e "\n${GREEN}[2] List Available Resources${NC}"
echo "Request: resources/list"
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"resources/list","id":2}' | python3 -c "
import sys, json
data = json.load(sys.stdin)
resources = data.get('result', {}).get('resources', [])
print('Available resources:')
for r in resources:
    print(f\"  - {r['uri']}\")
"

# 3. Compute SHA-256 hash
echo -e "\n${GREEN}[3] Compute SHA-256 Hash${NC}"
echo "Input: 'Hello World' (hex: 48656c6c6f20576f726c64)"
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"hash_sum",
      "arguments":{
        "plain_in_hex":"48656c6c6f20576f726c64",
        "required_hash_modes":["Sha256"]
      }
    },
    "id":3
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
content = data.get('result', {}).get('content', [])
if content:
    text = content[0].get('text', '{}')
    result = json.loads(text)
    sha256 = result.get('Results', {}).get('Sha256', {})
    print(f\"SHA-256: {sha256.get('hash_sum_in_hex', 'N/A')}\")
"

# 4. Generate random bytes
echo -e "\n${GREEN}[4] Generate Random Bytes${NC}"
echo "Request: 16 random bytes"
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"generate_random_data",
      "arguments":{
        "data_length":16
      }
    },
    "id":4
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
content = data.get('result', {}).get('content', [])
if content:
    text = content[0].get('text', '{}')
    result = json.loads(text)
    print(f\"Random bytes: {result.get('data_in_hex', 'N/A')}\")
"

# 5. Read resource: algorithm catalog
echo -e "\n${GREEN}[5] Read Resource: Algorithm Catalog${NC}"
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "method":"resources/read",
    "params":{
      "uri":"cipherhub://algorithms"
    },
    "id":5
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
contents = data.get('result', {}).get('contents', [])
if contents:
    text = contents[0].get('text', '{}')
    result = json.loads(text)
    print(f'Algorithm categories: {list(result.keys())[:5]}...')
"

# 6. Compute HMAC-SHA256
echo -e "\n${GREEN}[6] Compute HMAC-SHA256${NC}"
echo "Input: 'message' (hex: 6d657373616765) with a 32-byte key"
# Tip: convert any text to hex with:  echo -n "message" | xxd -p | tr -d '\n'
# Keys must meet the length constraints in the hmac_sum schema (32 bytes here)
curl -s -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"hmac_sum",
      "arguments":{
        "plain_in_hex":"6d657373616765",
        "key_in_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "required_hash_modes":["Sha256"]
      }
    },
    "id":6
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
content = data.get('result', {}).get('content', [])
if content:
    text = content[0].get('text', '{}')
    result = json.loads(text)
    hmac = result.get('Results', {}).get('Sha256', {})
    print(f\"HMAC-SHA256: {hmac.get('hmac_sum_in_hex', 'N/A')}\")
"

echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Examples complete!${NC}"
echo -e "${CYAN}========================================${NC}"
