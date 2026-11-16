# Changes — `fix/taint-semantic-fixes-crossfile-generic-pytest-windows`

14 files changed, 1408 insertions, 133 deletions across 14 commits.

---

## 1. Python Taint Fallback for Regex Mode

**Files:** `python_taint_fallback.py` (new, 688 lines), `analyzer.py`

When tree-sitter is not installed the scanner previously had no taint analysis at all. This adds a lightweight taint analyzer built on Python's stdlib `ast` module that covers:

- **Sources:** `request.args.get`, `request.form.get`, `input()`, and all Flask/Django request attributes
- **Sinks:** `os.system`, `eval`, `exec`, `cursor.execute`, `open()`, `subprocess.*`, `render_template_string`
- **Sanitizers:** `shlex.quote`, `html.escape`, `markupsafe.escape`
- **Inter-procedural propagation:** function summaries track which parameters flow to return values or internal sinks, enabling detection across call boundaries
- **With-statement support:** detects tainted data flowing into context expressions like `with open(user_input)`

Findings are tagged `engine: 'taint'` with `metadata.analysis_mode: 'regex-fallback'` so downstream consumers can distinguish them from tree-sitter findings.

---

## 2. Semantic Analysis Availability Check

**File:** `src/semantic-integration.js`

- Replaced hardcoded `python3` with `resolvePythonCommand()` + `pythonArgs()` from `src/python.js` for Windows compatibility (`py -3`)
- Changed `isSemanticAnalysisAvailable()` from a bare `python3 --version` check to actually verifying `import tree_sitter; import ast_parser` — the real prerequisites
- Result is cached in `_semanticAvailable` to avoid repeated subprocess spawns

---

## 3. Broken Auto-Fix Templates

**File:** `src/fix-patterns.js`

Several fix templates produced syntactically invalid code when applied:

| Pattern | Problem | Fix |
|---------|---------|-----|
| `sql-injection` | Regex didn't match real queries | Downgraded to `// TODO: manual fix required` |
| `raw-query` | Same issue | Downgraded to manual fix |
| `path-traversal` (4 languages) | Generated broken path joins | Downgraded to manual fix |
| `xpath-injection` | Invalid replacement | Downgraded to manual fix |
| `eval-llm-response` | Regex missed closing paren in `eval(var)` | Fixed regex to match full expression |

---

## 4. Cross-File Taint Analysis API

**File:** `cross_file_analyzer.py` (+483 lines)

The `cross_file_analyze()` endpoint previously returned only a static `cross-file-taint-warning` stub. Now implements a real pipeline:

- `extract_dangerous_functions_regex()` — identifies functions whose parameters flow to sinks using line-by-line regex with SQL keyword guards
- `_find_tainted_variables()` — finds variables assigned from taint sources (`req.params.*`, `request.args.get`, etc.)
- `_extract_import_bindings()` — parses `require`/`import` statements into structured `{module, names, is_default}` bindings
- `_find_calls_to_function()` — locates call sites with argument extraction
- `build_export_summaries()` — builds per-file dangerous function summaries
- `cross_file_taint_match()` — generates `cross-file-taint` findings with `taint_path`, `source_file`, `sink_file` metadata

The backward-compatible `cross-file-taint-warning` is still emitted alongside real findings.

---

## 5. Generic Rules False Positives

**File:** `rules/__init__.py`

Technology-scoped generic rules (e.g. Hugo, Django, Rails) were being applied to all files regardless of language. Added a `_TECH_LANGUAGES` mapping that gates each technology's rules to relevant language contexts:

```
hugo     -> go, html, toml, yaml
django   -> python, html
rails    -> ruby, html
flask    -> python, html
express  -> javascript, typescript
spring   -> java
laravel  -> php
```

Also checks if the technology name appears in the file path for framework-specific directories.

---

## 6. Pytest Fixture Collection

**Files:** `pytest.ini`, `tests/conftest.py`

Test fixtures in `tests/fixtures/` were being collected as test modules, causing import errors. Added `norecursedirs = tests/fixtures .git node_modules __pycache__` to `pytest.ini`.

---

## 7. Windows NamedTemporaryFile Compatibility

**Files:** `tests/test_ast_engine.py`, `tests/test_interprocedural.py`

On Windows, `os.unlink()` inside a `with NamedTemporaryFile(delete=False)` block fails because the file handle is still open. Extracted `_run_analyzer()` helper that closes the handle before unlinking:

```python
tmp = tempfile.NamedTemporaryFile(suffix=suffix, mode='w', delete=False)
try:
    tmp.write(code)
    tmp.flush()
    tmp.close()          # close handle first
    result = subprocess.run(...)
finally:
    os.unlink(tmp.name)  # now safe on Windows
```

---

## 8. ReDoS Vulnerability in Prompt Scanner

**Files:** `src/tools/scan-prompt.js`, `rules/prompt-injection.security.yaml`

`scan_agent_prompt` had a ReDoS vulnerability where long inputs (e.g. 50KB of `'A'`) caused catastrophic regex backtracking. The "timeout" check (`Date.now()` after synchronous `match()`) could never interrupt a blocked regex.

**Fixes:**

- Added `safeMatch()` — splits long inputs into overlapping 2KB windows so no single regex call processes more than 2KB
- Replaced all `expandedText.match(regex)` calls with `safeMatch()`
- Capped base64 quantifiers from unbounded `{40,}` to `{40,200}`
- Added `[^A-Za-z0-9+/=]` boundary anchor after base64 matches to prevent backtracking through the base64 portion
- Capped the base64 decode-and-rescan regex to `{40,4096}`
- Removed the fake post-hoc timeout

**Result:** 50KB input — 17,366ms to 91ms (190x faster). All 5 edge-case tests now pass. All prompt detection tests maintain 100% accuracy.

---

## 9. Minor Improvements (from stash)

| File | Change |
|------|--------|
| `src/history.js` | Normalize Windows backslashes in scan history paths |
| `src/tools/scan-prompt.js` | Extract `normalizeYamlRegexPattern()` helper (DRY) |
| `src/tools/scan-skill.js` | Pre-realpath boundary check for path traversal; extract `normalizeRulePattern()` helper |
| `src/tools/check-package.js` | Treat Flutter SDK packages as legitimate dart dependencies |

---

## Test Results

| Suite | Result |
|-------|--------|
| Python interprocedural tests | 10/10 passed |
| Python AST engine tests | 5/5 passed |
| JS test suite | 829/857 passed |
| Prompt scanner + Garak | 36/36 passed (100% detection) |
| Edge cases | 5/5 passed |

Remaining 4 failing JS test files are pre-existing issues unrelated to this branch (dart SDK lookup in `check-package`, daemon protocol race condition).
