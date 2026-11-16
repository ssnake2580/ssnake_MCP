# v3.7.0 Demo Output Example

This document shows the expected output when running the v3.7.0 demo.

## Scan Results

### Total Findings

When scanning `demo/v3.7.0-demo.py`:
- **Total Findings:** 126 issues
- **AST Findings:** 16
- **Taint Findings:** 110 ← **This is the inter-procedural magic!**
- **Regex Fallback:** 0

### Key Inter-Procedural Detections

#### ✅ Demo 1: `processed` Variable (Line 33)
```
Tainted variable 'processed' flows to sink.
Taint flow: request.args.get(...) -> Line 33: processed = ... user_cmd ...
```
**What this means:** The scanner tracked taint from `user_cmd` (line 32), through the `process_user_input()` function call, and detected it reaching `os.system(processed)` on line 33.

#### ✅ Demo 3: `hop3` Variable (Line 88) - 3-Hop Chain!
```
Tainted variable 'hop3' flows to sink.
Taint flow: Line 86: hop1 = ... user_input ...
           -> Line 87: hop2 = ... hop1 ...
           -> Line 88: hop3 = ... hop2 ...
```
**What this means:** The scanner tracked taint through **THREE function calls**:
1. `user_input` → `step1_receive()` → `hop1`
2. `hop1` → `step2_process()` → `hop2`
3. `hop2` → `step3_format()` → `hop3`
4. Finally detected `hop3` reaching `os.system()`

This is impossible with traditional single-function taint analysis!

#### ✅ Demo 4: Internal Sink Detection
The scanner detects when `user_cmd` is passed to `execute_command()`, even though the sink (`os.system()`) is **inside** that function, not in the calling function.

#### ✅ Demo 5: Sanitizer Smart Detection
When `sanitize_input()` is called on tainted data, the scanner recognizes it as a sanitizer and **does NOT produce a false positive**. You'll notice `safe_cmd` is not flagged as tainted.

---

## Performance Demo Output

### Daemon Caching Performance

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

### What's Happening:

1. **First Scan (Cold):** ~4 seconds
   - Daemon starts up
   - Loads all 1,700+ security rules
   - Parses AST
   - Builds call graph
   - Runs taint analysis
   - Caches result keyed by `(file_path, mtime)`

2. **Second Scan (Cached):** ~0-1ms (instant!)
   - Daemon already running
   - Checks file mtime (modification time)
   - File unchanged → returns cached result
   - **~4000x faster!**

3. **Third Scan:** Same as second - cache hit!

### Real-World Impact:

| Use Case | Before v3.7.0 | v3.7.0 (Cached) | Speedup |
|----------|---------------|-----------------|---------|
| IDE integration (watch mode) | 4s per keystroke ❌ | 1ms ⚡ | 4000x |
| Pre-commit hook (10 files) | 40s | ~10ms | 4000x |
| CI/CD (100 files, 3 runs) | 1200s (20min) | ~300s (5min) | 4x |

---

## Command Line Examples

### Run Full Demo
```bash
./demo/run-v3.7.0-demo.sh
```

### Scan Demo File Manually
```bash
# Full scan
python3 analyzer.py demo/v3.7.0-demo.py > results.json

# Show taint findings only
python3 analyzer.py demo/v3.7.0-demo.py 2>&1 | jq '.[] | select(.engine == "taint")'

# Count taint findings
python3 analyzer.py demo/v3.7.0-demo.py 2>&1 | jq '[.[] | select(.engine == "taint")] | length'
```

### Test Daemon Performance
```bash
# First scan (cold)
time python3 analyzer.py demo/v3.7.0-demo.py > /dev/null

# Second scan (should be ~4000x faster!)
time python3 analyzer.py demo/v3.7.0-demo.py > /dev/null
```

---

## Sample Finding Output

Here's a real inter-procedural taint finding from the demo:

```json
{
  "ruleId": "flask-command-injection-system",
  "message": "[Flask Command Injection System] Command Injection vulnerability detected. User input from Flask request flows to os.system() which executes shell commands. An attacker could execute arbitrary system commands. Use subprocess with shell=False and argument lists instead.\n\nTaint flow: Source: request.args.get(...) -> Line 86: hop1 = ... user_input ... -> Line 87: hop2 = ... hop1 ... -> Line 88: hop3 = ... hop2 ...\n\nTainted variable 'hop3' flows to sink.",
  "line": 88,
  "column": 4,
  "length": 15,
  "severity": "error",
  "confidence": "HIGH",
  "metadata": {
    "cwe": ["CWE-78: OS Command Injection"],
    "owasp": ["A03:2021 - Injection", "A05:2025 - Injection"],
    "category": "security",
    "technology": ["flask"],
    "subcategory": ["vuln"],
    "impact": "CRITICAL",
    "likelihood": "HIGH",
    "confidence": "HIGH",
    "fix": "Use subprocess with shell=False:\nsubprocess.run(['ping', '-c', '1', host], shell=False)\n",
    "taint_source": "request.args.get(...)",
    "taint_source_line": 85,
    "tainted_variable": "hop3"
  },
  "engine": "taint"
}
```

### Key Fields:

- **`tainted_variable`**: `hop3` - The variable that carries tainted data
- **`taint_source`**: `request.args.get(...)` - Where the taint originates
- **`taint_source_line`**: 85 - Line number of the source
- **Taint flow description**: Shows the exact path through functions:
  ```
  request.args.get(...)
  → Line 86: hop1 = ... user_input ...
  → Line 87: hop2 = ... hop1 ...
  → Line 88: hop3 = ... hop2 ...
  ```

---

## Comparison: Before vs After

### Before v3.7.0 (Single-Function Taint Analysis)

```python
def vulnerable():
    user_cmd = request.args.get('cmd')      # ✅ Source detected
    processed = process_user_input(user_cmd)  # ❌ Lost track here!
    os.system(processed)  # ❌ MISSED - couldn't connect dots
```
**Result:** ❌ No finding (taint lost at function boundary)

### v3.7.0 (Inter-Procedural Taint Analysis)

```python
def vulnerable():
    user_cmd = request.args.get('cmd')      # ✅ Source detected
    processed = process_user_input(user_cmd)  # ✅ Tracks through function!
    os.system(processed)  # ✅ DETECTED - complete path traced
```
**Result:** ✅ Finding with full taint path:
```
Source: request.args.get(...)
→ Line 33: processed = ... user_cmd ...
→ Tainted variable 'processed' flows to sink
```

---

## Try It Yourself!

1. **Install the package:**
   ```bash
   npm install -g agent-security-scanner-mcp@3.7.0
   ```

2. **Run the demo:**
   ```bash
   cd /path/to/agent-security-scanner-mcp
   ./demo/run-v3.7.0-demo.sh
   ```

3. **Create your own test:**
   ```python
   # test-interprocedural.py
   from flask import Flask, request
   import os

   def process(data):
       return "cmd: " + data

   @app.route('/vuln')
   def vuln():
       user_input = request.args.get('input')
       processed = process(user_input)  # Will this be detected?
       os.system(processed)  # YES! v3.7.0 will find it!
   ```

4. **Scan it:**
   ```bash
   python3 analyzer.py test-interprocedural.py
   ```

You should see a taint finding for the `processed` variable!

---

## Learn More

- **GitHub:** https://github.com/sinewaveai/agent-security-scanner-mcp
- **npm:** https://npmjs.com/package/agent-security-scanner-mcp
- **Test Report:** ../TEST-REPORT-v3.7.0.md
- **Changelog:** ../README.md#v370

---

**Questions?** Open an issue on GitHub or try the demo yourself!
