# v3.7.0 Demo: Inter-Procedural Taint Analysis & Daemon Caching

This demo showcases the two major features introduced in v3.7.0:
1. **Inter-Procedural Taint Analysis** - Tracks vulnerabilities across function boundaries
2. **Python Daemon with LRU Caching** - ~4000x faster repeat scans

## Quick Start

```bash
# Run the full demo
./demo/run-v3.7.0-demo.sh
```

## What You'll See

### Part 1: Inter-Procedural Taint Analysis

The demo will scan `v3.7.0-demo.py` and detect **7 different attack scenarios**:

#### ✅ DEMO 1: Basic Parameter-to-Return Flow
```python
def process_user_input(data):
    return "command: " + data

user_cmd = request.args.get('cmd')      # Source
processed = process_user_input(user_cmd)  # Taint propagates!
os.system(processed)                     # 💥 DETECTED
```
**Previous versions:** ❌ Missed (couldn't see through function)
**v3.7.0:** ✅ Detected (tracks taint through `process_user_input()`)

#### ✅ DEMO 2: Source-Returning Functions
```python
def get_user_data():
    return request.args.get('input')  # Returns tainted data

user_input = get_user_data()  # Function returns taint
os.system(user_input)         # 💥 DETECTED
```
**Previous versions:** ❌ Missed (didn't track return values)
**v3.7.0:** ✅ Detected (recognizes source-returning functions)

#### ✅ DEMO 3: Multi-Hop Chains (3+ Functions)
```python
user_input = request.args.get('data')
hop1 = step1_receive(user_input)  # Hop 1
hop2 = step2_process(hop1)        # Hop 2
hop3 = step3_format(hop2)         # Hop 3
os.system(hop3)                   # 💥 DETECTED
```
**Previous versions:** ❌ Missed (couldn't track multiple hops)
**v3.7.0:** ✅ Detected (tracks through 3+ function calls)

#### ✅ DEMO 4: Internal Sinks
```python
def execute_command(cmd):
    os.system(cmd)  # Sink INSIDE function

user_cmd = request.args.get('cmd')
execute_command(user_cmd)  # 💥 DETECTED
```
**Previous versions:** ❌ Missed (couldn't see into called functions)
**v3.7.0:** ✅ Detected (finds sinks inside functions)

#### ✅ DEMO 5: Sanitizer Detection
```python
def sanitize_input(data):
    return data.replace(";", "").replace("&", "")

user_cmd = request.args.get('cmd')
safe_cmd = sanitize_input(user_cmd)  # Sanitizer blocks taint
os.system(safe_cmd)                  # ✅ NO FALSE POSITIVE
```
**Previous versions:** ⚠️ False positive (couldn't see sanitizer)
**v3.7.0:** ✅ Smart (recognizes sanitizers, no false alarm)

#### ✅ DEMO 6: Complex Real-World Chain
```python
# Multi-step attack: request → validate → class method → helper → sink
user_data = request.args.get('action')
validated = validate_input(user_data)
command = builder.build_command(validated)
log_and_execute(command)  # 💥 DETECTED (complex chain!)
```
**Previous versions:** ❌ Missed (too complex)
**v3.7.0:** ✅ Detected (handles real-world complexity)

#### ✅ DEMO 7: SQL Injection Chain
```python
user_filter = get_user_filter()           # Source function
query = build_query('users', user_filter) # Taint propagates
execute_query(query)                      # 💥 DETECTED (sink in function)
```
**Previous versions:** ❌ Missed
**v3.7.0:** ✅ Detected (SQL injection through functions)

---

### Part 2: Daemon Caching Performance

The demo will run **3 scans** to show the caching speedup:

```
📊 SCAN 1 (Cold - No Cache):
   Time: 4150ms

📊 SCAN 2 (Warm - From Cache):
   Time: 0ms
   Speedup: ∞x faster! 🚀

📊 SCAN 3 (Warm - From Cache):
   Time: 1ms
   Speedup: 4150x faster! 🚀
```

**How it works:**
- First scan: Runs full analysis, caches result
- Subsequent scans: Instant cache lookup (checks file mtime)
- Perfect for: IDE integrations, watch mode, pre-commit hooks

---

## Manual Testing

### Test Inter-Procedural Taint Analysis

```bash
# Scan the demo file
python3 analyzer.py demo/v3.7.0-demo.py

# Look for taint findings
python3 analyzer.py demo/v3.7.0-demo.py 2>&1 | grep -A 5 "tainted_variable"
```

You should see taint findings for variables like:
- `processed` (demo 1)
- `hop3` (demo 3)
- Many more!

### Test Daemon Caching

```bash
# First scan (cold)
time python3 analyzer.py demo/v3.7.0-demo.py > /dev/null

# Second scan (cached) - should be ~4000x faster!
time python3 analyzer.py demo/v3.7.0-demo.py > /dev/null
```

Or use the daemon client directly:

```javascript
const { getDaemonClient } = require('./src/daemon-client.js');

const client = getDaemonClient();

// First scan
const start1 = Date.now();
await client.analyze('demo/v3.7.0-demo.py');
console.log(`Time: ${Date.now() - start1}ms`);

// Second scan (cached!)
const start2 = Date.now();
await client.analyze('demo/v3.7.0-demo.py');
console.log(`Time: ${Date.now() - start2}ms`);  // ~0-1ms!

await client.shutdown();
```

---

## Expected Output

The demo script produces colorized output showing:

1. **Inter-procedural taint findings** detected in each demo scenario
2. **Performance metrics** for daemon caching
3. **Summary statistics** comparing v3.7.0 to previous versions

Example summary:
```
✅ v3.7.0 New Features:

  1. Inter-Procedural Taint Analysis
     • Tracks taint across function boundaries
     • Detects multi-hop chains (3+ calls)
     • Finds internal sinks
     • Recognizes sanitizers

  2. Python Daemon with LRU Caching
     • ~4000x faster repeat scans
     • Auto-start/shutdown
     • Health monitoring

📈 Impact:

  • Detects 20+ complex vulnerabilities in demo file
  • Finds bugs that previous versions missed
  • 4000x faster for IDE integrations & watch mode
  • Perfect for pre-commit hooks & CI/CD
```

---

## Files

- `v3.7.0-demo.py` - Intentionally vulnerable Flask app with 7 attack scenarios
- `run-v3.7.0-demo.sh` - Interactive demo script with colored output
- `README.md` - This file

---

## Safety Notice

⚠️ **WARNING:** `v3.7.0-demo.py` contains **intentional security vulnerabilities** for demonstration purposes.

**DO NOT:**
- Run the Flask server in production
- Expose it to the internet
- Use any code patterns from this file in real applications

**DO:**
- Use it only for testing the security scanner
- Learn from the vulnerability patterns
- Share it to demonstrate v3.7.0 features

---

## Learn More

- **Documentation:** https://github.com/sinewaveai/agent-security-scanner-mcp
- **npm Package:** https://npmjs.com/package/agent-security-scanner-mcp
- **Full Test Report:** ../TEST-REPORT-v3.7.0.md
