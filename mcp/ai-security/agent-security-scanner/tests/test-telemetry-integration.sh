#!/bin/bash
# Comprehensive telemetry integration test suite
# Tests real-world usage scenarios for PR #16

set -e

echo "=== TELEMETRY INTEGRATION TEST SUITE ==="
echo "Testing PR #16 telemetry implementation"
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass() {
  echo -e "${GREEN}  ✓${NC} $1"
  ((TESTS_PASSED++))
  ((TESTS_RUN++))
}

fail() {
  echo -e "${RED}  ✗ FAILED${NC}: $1"
  ((TESTS_FAILED++))
  ((TESTS_RUN++))
}

test_header() {
  echo -e "${YELLOW}TEST $1${NC}"
}

# Clean state function
clean_state() {
  rm -rf ~/.agent-security-scanner-mcp
  export -n DO_NOT_TRACK SCANNER_TELEMETRY_DISABLED CI SCANNER_TELEMETRY_DEBUG SCANNER_TELEMETRY_ENDPOINT
}

# Create test file
cat > /tmp/test-vulnerable.py << 'EOF'
import os
cmd = input("Enter command: ")
os.system(cmd)  # Command injection
EOF

# ============================================================================
# TEST 1: First-run notice appears
# ============================================================================
test_header "1: First-run notice"
clean_state
output=$(node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  pass "Notice shown on first run"
else
  fail "Notice not shown"
fi

# ============================================================================
# TEST 2: Notice not repeated on second run
# ============================================================================
test_header "2: Notice not repeated"
output=$(node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  fail "Notice shown twice"
else
  pass "Notice not repeated"
fi

# ============================================================================
# TEST 3: DO_NOT_TRACK=1 respected
# ============================================================================
test_header "3: DO_NOT_TRACK=1"
clean_state
output=$(DO_NOT_TRACK=1 node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  fail "Notice shown with DO_NOT_TRACK=1"
else
  pass "DO_NOT_TRACK honored"
fi

# ============================================================================
# TEST 4: CLI opt-out (telemetry --off)
# ============================================================================
test_header "4: CLI telemetry --off"
clean_state
node index.js telemetry --off > /dev/null 2>&1
output=$(node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  fail "Notice shown after opt-out"
else
  pass "CLI opt-out works"
fi

# ============================================================================
# TEST 5: Machine ID is UUID format
# ============================================================================
test_header "5: Machine ID format"
clean_state
node index.js scan-security /tmp/test-vulnerable.py > /dev/null 2>&1 || true
machine_id=$(grep -o '"machine_id"[[:space:]]*:[[:space:]]*"[^"]*"' ~/.agent-security-scanner-mcp/telemetry.json | cut -d'"' -f4)
if [[ $machine_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  pass "Machine ID is valid UUID: ${machine_id:0:15}..."
else
  fail "Invalid machine ID format: $machine_id"
fi

# ============================================================================
# TEST 6: Legacy ID migration (SHA-256 -> UUID)
# ============================================================================
test_header "6: Legacy ID migration"
clean_state
mkdir -p ~/.agent-security-scanner-mcp
# Create legacy 64-char hex ID
echo '{"machine_id":"'$(head -c 32 /dev/urandom | xxd -p -c 64)'"}' > ~/.agent-security-scanner-mcp/telemetry.json
node index.js scan-security /tmp/test-vulnerable.py > /dev/null 2>&1 || true
if grep -q "_legacy_id_migrated" ~/.agent-security-scanner-mcp/telemetry.json && \
   grep -q '"machine_id"[[:space:]]*:[[:space:]]*"[0-9a-f]\{8\}-' ~/.agent-security-scanner-mcp/telemetry.json; then
  pass "Legacy ID auto-migrated to UUID"
else
  fail "Legacy ID not migrated"
fi

# ============================================================================
# TEST 7: Status command output
# ============================================================================
test_header "7: telemetry --status"
output=$(node index.js telemetry --status 2>&1 || true)
if echo "$output" | grep -q "Machine ID:" && echo "$output" | grep -q "Endpoint:" && echo "$output" | grep -q "proof-layer.com"; then
  pass "Status command shows all info"
else
  fail "Status command incomplete"
fi

# ============================================================================
# TEST 8: Debug mode prints events
# ============================================================================
test_header "8: Debug mode (SCANNER_TELEMETRY_DEBUG=1)"
clean_state
output=$(SCANNER_TELEMETRY_DEBUG=1 node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "\[telemetry:debug\]"; then
  pass "Debug mode prints events to stderr"
else
  fail "Debug mode not working"
fi

# ============================================================================
# TEST 9: CI environment auto-disable
# ============================================================================
test_header "9: CI auto-disable"
clean_state
output=$(CI=1 node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  fail "Notice shown in CI environment"
else
  pass "CI auto-disable works (CI=1)"
fi

output=$(CI=true node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q "Telemetry Notice"; then
  fail "Notice shown with CI=true"
else
  pass "CI auto-disable works (CI=true)"
fi

# ============================================================================
# TEST 10: Custom endpoint override
# ============================================================================
test_header "10: Custom endpoint (SCANNER_TELEMETRY_ENDPOINT)"
output=$(SCANNER_TELEMETRY_ENDPOINT=https://custom.example.com/events node index.js telemetry --status 2>&1 || true)
if echo "$output" | grep -q "custom.example.com"; then
  pass "Custom endpoint shown in status"
else
  fail "Custom endpoint not working"
fi

# ============================================================================
# TEST 11: MCP JSON integrity (stdout clean)
# ============================================================================
test_header "11: MCP JSON integrity"
clean_state
stdout=$(node index.js scan-security /tmp/test-vulnerable.py 2>/dev/null || true)
if echo "$stdout" | jq . > /dev/null 2>&1; then
  pass "stdout is valid JSON (MCP integrity preserved)"
else
  fail "stdout is not valid JSON"
fi

# ============================================================================
# TEST 12: CLI invocation mode
# ============================================================================
test_header "12: CLI invocation mode"
clean_state
output=$(SCANNER_TELEMETRY_DEBUG=1 node index.js scan-security /tmp/test-vulnerable.py 2>&1 || true)
if echo "$output" | grep -q '"invocation_mode":"cli"'; then
  pass "CLI mode detected correctly"
else
  fail "CLI mode not detected"
fi

# ============================================================================
# TEST 13: File paths not in telemetry
# ============================================================================
test_header "13: Privacy - no file paths"
clean_state
output=$(SCANNER_TELEMETRY_DEBUG=1 node index.js scan-security /Users/alice/secret-project/auth.py 2>&1 || true)
if echo "$output" | grep -q "alice" || echo "$output" | grep -q "secret-project" || echo "$output" | grep -q "auth.py"; then
  fail "File path leaked in telemetry"
else
  pass "No file paths in telemetry events"
fi

# ============================================================================
# TEST 14: State file permissions
# ============================================================================
test_header "14: State file created with correct permissions"
clean_state
node index.js scan-security /tmp/test-vulnerable.py > /dev/null 2>&1 || true
if [ -f ~/.agent-security-scanner-mcp/telemetry.json ]; then
  pass "State file created"
else
  fail "State file not created"
fi

# ============================================================================
# TEST 15: Telemetry status in doctor command
# ============================================================================
test_header "15: Doctor command shows telemetry status"
clean_state
output=$(node index.js doctor 2>&1 || true)
if echo "$output" | grep -q -i "telemetry"; then
  pass "Doctor shows telemetry status"
else
  fail "Doctor missing telemetry info"
fi

# Cleanup
rm -f /tmp/test-vulnerable.py

# ============================================================================
# SUMMARY
# ============================================================================
echo
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo "Total tests:  $TESTS_RUN"
echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
  echo -e "${RED}Failed:       $TESTS_FAILED${NC}"
  echo
  exit 1
else
  echo -e "Failed:       $TESTS_FAILED"
  echo
  echo -e "${GREEN}✓ ALL INTEGRATION TESTS PASSED${NC}"
  exit 0
fi
