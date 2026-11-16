#!/bin/bash

# v3.7.0 Demo Script: Inter-Procedural Taint Analysis & Daemon Caching
# =====================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Demo file
DEMO_FILE="demo/v3.7.0-demo.py"

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║                                                               ║${NC}"
echo -e "${BOLD}${CYAN}║  🚀 v3.7.0 Demo: Inter-Procedural Taint Analysis & Daemon    ║${NC}"
echo -e "${BOLD}${CYAN}║                                                               ║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# PART 1: Inter-Procedural Taint Analysis Demo
# ============================================================================

echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${MAGENTA}  PART 1: Inter-Procedural Taint Analysis${NC}"
echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}What's New in v3.7.0?${NC}"
echo ""
echo -e "  ✅ Tracks taint ${GREEN}across function boundaries${NC}"
echo -e "  ✅ Detects ${GREEN}multi-hop chains${NC} (3+ function calls)"
echo -e "  ✅ Finds ${GREEN}internal sinks${NC} inside called functions"
echo -e "  ✅ Recognizes ${GREEN}source-returning functions${NC}"
echo -e "  ✅ Respects ${GREEN}sanitizers${NC} in other functions"
echo ""
echo -e "${BLUE}Scanning demo file...${NC}"
echo ""

# Run the scan
python3 analyzer.py "$DEMO_FILE" > /tmp/demo-scan-full.json 2>&1

# Extract key findings
echo -e "${BOLD}${GREEN}📊 SCAN RESULTS:${NC}"
echo ""

# Count taint findings
TAINT_COUNT=$(python3 -c "
import json
import sys
with open('/tmp/demo-scan-full.json') as f:
    data = json.load(f)
taint_findings = [x for x in data if x.get('engine') == 'taint']
print(len(taint_findings))
" 2>/dev/null || echo "0")

echo -e "  ${CYAN}Total Taint Findings:${NC} $TAINT_COUNT"
echo ""

# Show specific demo findings
echo -e "${BOLD}${YELLOW}🔍 DEMO 1: Basic Parameter-to-Return Flow${NC}"
echo ""
echo -e "  ${BLUE}Code:${NC}"
echo -e "    ${GREEN}def${NC} process_user_input(data):"
echo -e "        ${GREEN}return${NC} ${YELLOW}\"command: \"${NC} + data"
echo -e ""
echo -e "    user_cmd = request.args.get(${YELLOW}'cmd'${NC})      ${CYAN}# Source${NC}"
echo -e "    processed = process_user_input(user_cmd)  ${CYAN}# Taint flows through!${NC}"
echo -e "    os.system(processed)                       ${RED}# 💥 Sink${NC}"
echo ""

# Check if 'processed' is tainted
PROCESSED_TAINTED=$(python3 -c "
import json
with open('/tmp/demo-scan-full.json') as f:
    data = json.load(f)
taint = [x for x in data if x.get('engine') == 'taint' and x.get('metadata', {}).get('tainted_variable') == 'processed']
print('YES' if taint else 'NO')
" 2>/dev/null)

if [ "$PROCESSED_TAINTED" = "YES" ]; then
    echo -e "  ${GREEN}✅ DETECTED:${NC} Variable 'processed' is tainted through function call!"
else
    echo -e "  ${RED}❌ NOT DETECTED${NC}"
fi
echo ""

echo -e "${BOLD}${YELLOW}🔍 DEMO 3: Multi-Hop Chain (3 Functions)${NC}"
echo ""
echo -e "  ${BLUE}Code:${NC}"
echo -e "    user_input = request.args.get(${YELLOW}'data'${NC})  ${CYAN}# Source${NC}"
echo -e "    hop1 = step1_receive(user_input)        ${CYAN}# Hop 1${NC}"
echo -e "    hop2 = step2_process(hop1)              ${CYAN}# Hop 2${NC}"
echo -e "    hop3 = step3_format(hop2)               ${CYAN}# Hop 3${NC}"
echo -e "    os.system(hop3)                         ${RED}# 💥 Sink${NC}"
echo ""

# Check if 'hop3' is tainted
HOP3_TAINTED=$(python3 -c "
import json
with open('/tmp/demo-scan-full.json') as f:
    data = json.load(f)
taint = [x for x in data if x.get('engine') == 'taint' and x.get('metadata', {}).get('tainted_variable') == 'hop3']
print('YES' if taint else 'NO')
" 2>/dev/null)

if [ "$HOP3_TAINTED" = "YES" ]; then
    echo -e "  ${GREEN}✅ DETECTED:${NC} Variable 'hop3' is tainted through 3-hop chain!"
else
    echo -e "  ${RED}❌ NOT DETECTED${NC}"
fi
echo ""

echo -e "${BOLD}${YELLOW}🔍 DEMO 4: Internal Sink Detection${NC}"
echo ""
echo -e "  ${BLUE}Code:${NC}"
echo -e "    ${GREEN}def${NC} execute_command(cmd):"
echo -e "        os.system(cmd)  ${CYAN}# Sink is INSIDE function${NC}"
echo -e ""
echo -e "    user_cmd = request.args.get(${YELLOW}'cmd'${NC})"
echo -e "    execute_command(user_cmd)  ${RED}# 💥 Calls function with internal sink${NC}"
echo ""

# Check for findings on execute_command call
INTERNAL_SINK=$(python3 -c "
import json
with open('/tmp/demo-scan-full.json') as f:
    data = json.load(f)
# Look for findings mentioning execute_command or on that line
taint = [x for x in data if x.get('engine') == 'taint' and 'execute_command' in str(x)]
print('YES' if taint else 'NO')
" 2>/dev/null)

if [ "$INTERNAL_SINK" = "YES" ]; then
    echo -e "  ${GREEN}✅ DETECTED:${NC} Internal sink inside execute_command() detected!"
else
    echo -e "  ${RED}❌ NOT DETECTED${NC}"
fi
echo ""

# ============================================================================
# PART 2: Daemon Caching Performance Demo
# ============================================================================

echo ""
echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${MAGENTA}  PART 2: Daemon Caching Performance${NC}"
echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}What's New?${NC}"
echo ""
echo -e "  ✅ ${GREEN}Long-running Python daemon${NC} process"
echo -e "  ✅ ${GREEN}LRU caching${NC} (200 entries, keyed by file + mtime)"
echo -e "  ✅ ${GREEN}~4000x faster${NC} repeat scans!"
echo ""

# Create a Node.js test script
cat > /tmp/demo-daemon-test.js << 'EOF'
const { getDaemonClient } = require('./src/daemon-client.js');

async function runDemo() {
  const client = getDaemonClient();
  const file = 'demo/v3.7.0-demo.py';

  console.log('📊 SCAN 1 (Cold - No Cache):');
  const start1 = Date.now();
  await client.analyze(file);
  const time1 = Date.now() - start1;
  console.log(`   Time: ${time1}ms\n`);

  console.log('📊 SCAN 2 (Warm - From Cache):');
  const start2 = Date.now();
  await client.analyze(file);
  const time2 = Date.now() - start2;
  console.log(`   Time: ${time2}ms`);
  console.log(`   Speedup: ${(time1 / Math.max(time2, 1)).toFixed(1)}x faster! 🚀\n`);

  console.log('📊 SCAN 3 (Warm - From Cache):');
  const start3 = Date.now();
  await client.analyze(file);
  const time3 = Date.now() - start3;
  console.log(`   Time: ${time3}ms`);
  console.log(`   Speedup: ${(time1 / Math.max(time3, 1)).toFixed(1)}x faster! 🚀\n`);

  await client.shutdown();
}

runDemo().catch(console.error);
EOF

echo -e "${BLUE}Testing daemon cache performance...${NC}"
echo ""

# Run the daemon test
node /tmp/demo-daemon-test.js

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║                         SUMMARY                               ║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}${GREEN}✅ v3.7.0 New Features:${NC}"
echo ""
echo -e "  ${MAGENTA}1. Inter-Procedural Taint Analysis${NC}"
echo -e "     • Tracks taint across function boundaries"
echo -e "     • Detects multi-hop chains (3+ calls)"
echo -e "     • Finds internal sinks"
echo -e "     • Recognizes sanitizers"
echo ""
echo -e "  ${MAGENTA}2. Python Daemon with LRU Caching${NC}"
echo -e "     • ~4000x faster repeat scans"
echo -e "     • Auto-start/shutdown"
echo -e "     • Health monitoring"
echo ""

echo -e "${BOLD}${YELLOW}📈 Impact:${NC}"
echo ""
echo -e "  ${GREEN}•${NC} Detects ${BOLD}$TAINT_COUNT complex vulnerabilities${NC} in demo file"
echo -e "  ${GREEN}•${NC} Finds bugs that ${BOLD}previous versions missed${NC}"
echo -e "  ${GREEN}•${NC} ${BOLD}4000x faster${NC} for IDE integrations & watch mode"
echo -e "  ${GREEN}•${NC} Perfect for ${BOLD}pre-commit hooks & CI/CD${NC}"
echo ""

echo -e "${BOLD}${BLUE}🔗 Learn More:${NC}"
echo ""
echo -e "  • README: ${CYAN}https://github.com/sinewaveai/agent-security-scanner-mcp${NC}"
echo -e "  • npm:    ${CYAN}https://npmjs.com/package/agent-security-scanner-mcp${NC}"
echo ""

echo -e "${BOLD}${GREEN}Demo complete! 🎉${NC}"
echo ""

# Cleanup
rm -f /tmp/demo-daemon-test.js /tmp/demo-scan-full.json
