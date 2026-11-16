#!/usr/bin/env bash
# quickstart.sh — live demo of pd-mcp's recon chain.
#
# Passive-only: subfinder (passive sources) → dnsx (resolution) → httpx (probing).
# No port scanning, no vulnerability scanning. Safe to run against any domain
# you own or that permits recon (default: example.com).
#
# Usage: ./examples/quickstart.sh [domain]
set -euo pipefail

DOMAIN="${1:-example.com}"
PD_TOOLS_DIR="${PD_TOOLS_DIR:-$HOME/.pdtm/go/bin}"

for bin in subfinder dnsx httpx; do
  if [[ ! -x "$PD_TOOLS_DIR/$bin" ]]; then
    echo "missing: $PD_TOOLS_DIR/$bin (set PD_TOOLS_DIR or install via pdtm)" >&2
    exit 1
  fi
done

echo "=== 1/3 subfinder: passive subdomain enumeration for $DOMAIN ==="
"$PD_TOOLS_DIR/subfinder" -silent -d "$DOMAIN" -o /tmp/pd-demo-subs.txt
wc -l < /tmp/pd-demo-subs.txt | xargs echo "subdomains found:"
head -5 /tmp/pd-demo-subs.txt

echo
echo "=== 2/3 dnsx: resolve A records ==="
"$PD_TOOLS_DIR/dnsx" -silent -a -l /tmp/pd-demo-subs.txt -o /tmp/pd-demo-dns.txt
wc -l < /tmp/pd-demo-dns.txt | xargs echo "resolved hosts:"

echo
echo "=== 3/3 httpx: probe live HTTP(S) ==="
"$PD_TOOLS_DIR/httpx" -silent -l /tmp/pd-demo-dns.txt -o /tmp/pd-demo-http.txt
wc -l < /tmp/pd-demo-http.txt | xargs echo "live hosts:"
head -5 /tmp/pd-demo-http.txt

echo
echo "done — full chain ran in one script, same as the MCP tools do per-call."
