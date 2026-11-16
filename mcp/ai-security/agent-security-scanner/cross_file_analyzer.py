#!/usr/bin/env python3
"""Cross-file taint analysis for security scanning.

Builds an import graph across local files, runs per-file analysis,
and propagates taint warnings when a file imports from another file
that has ERROR-severity findings.  Also performs parameter-aware
cross-file taint matching by building export summaries of dangerous
functions and tracing tainted data through import bindings and call sites.
"""

import json
import os
import re
import sys

# Import the per-file analyzer
from analyzer import analyze_file


# ---------------------------------------------------------------------------
# Sink detection patterns used by extract_dangerous_functions_regex
# ---------------------------------------------------------------------------

# (regex matching a sink call inside a function body, rule_id)
_JS_SINK_PATTERNS = [
    # SQL injection: string ending quote/tick then + variable, on a line with SQL keyword
    # This broad pattern catches "...WHERE id = " + id  and  "...LIKE '%" + term
    (r'''["'`]\s*\+\s*(\w+)''', 'sql-injection', r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b'),
    # SQL injection via template literal
    (r'''`(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b[^`]*\$\{(\w+)\}''', 'sql-injection', None),
    # eval()
    (r'''\beval\s*\(\s*(\w+)\s*\)''', 'code-injection', None),
    # child_process.exec
    (r'''\bexec\s*\(\s*(\w+)''', 'command-injection', None),
]

_PY_SINK_PATTERNS = [
    (r'''\bcursor\.execute\s*\(\s*["'].*\+\s*(\w+)''', 'sql-injection', None),
    (r'''\bcursor\.execute\s*\(\s*f["'].*\{(\w+)\}''', 'sql-injection', None),
    (r'''\beval\s*\(\s*(\w+)\s*\)''', 'code-injection', None),
    (r'''\bexec\s*\(\s*(\w+)''', 'code-injection', None),
    (r'''\bos\.system\s*\(\s*(\w+)''', 'command-injection', None),
    (r'''\bsubprocess\.(?:call|run|Popen)\s*\(\s*(\w+)''', 'command-injection', None),
]

# ---------------------------------------------------------------------------
# Taint source patterns used by _find_tainted_variables
# ---------------------------------------------------------------------------

_JS_TAINT_SOURCES = [
    # Express: req.params.id, req.query.q, etc. — capture the full accessor
    (r'''(?:const|let|var)\s+(\w+)\s*=\s*(req\.(?:params|query|body|headers|cookies)(?:\.\w+|\[[^\]]+\]))''',),
]

_PY_TAINT_SOURCES = [
    (r'''(\w+)\s*=\s*(request\.(?:args|form|values|json|data|files|cookies|headers)(?:\.get\([^)]*\)|\[[^\]]+\]))''',),
    (r'''(\w+)\s*=\s*(request\.GET(?:\.get\([^)]*\)|\[[^\]]+\]))''',),
    (r'''(\w+)\s*=\s*(request\.POST(?:\.get\([^)]*\)|\[[^\]]+\]))''',),
    (r'''(\w+)\s*=\s*(input\s*\([^)]*\))''',),
]


# ---------------------------------------------------------------------------
# Function extraction helpers
# ---------------------------------------------------------------------------

# Regular function: function name(params) { ... }
_JS_FUNC_RE = re.compile(
    r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)'
)
# Arrow / const: const name = (params) => { ... }  or const name = function(params) { ... }
_JS_ARROW_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|(\w+))\s*=>'
)
_JS_CONST_FUNC_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)'
)
# Python
_PY_FUNC_RE = re.compile(
    r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*:'
)


def _extract_js_functions(source):
    """Extract function definitions from JavaScript/TypeScript source."""
    functions = []
    lines = source.split('\n')

    for i, line in enumerate(lines):
        for regex in (_JS_FUNC_RE, _JS_ARROW_RE, _JS_CONST_FUNC_RE):
            m = regex.search(line)
            if m:
                name = m.group(1)
                params_str = m.group(2) if m.lastindex >= 2 and m.group(2) else ''
                if regex == _JS_ARROW_RE and m.group(3):
                    params_str = m.group(3)
                params = [p.strip().split('=')[0].strip()
                          for p in params_str.split(',') if p.strip()]
                # Find function body end (simple brace counting)
                body_start = i
                body_lines = []
                brace_count = 0
                started = False
                for j in range(i, min(i + 200, len(lines))):
                    body_lines.append(lines[j])
                    brace_count += lines[j].count('{') - lines[j].count('}')
                    if '{' in lines[j]:
                        started = True
                    if started and brace_count <= 0:
                        break
                functions.append({
                    'name': name,
                    'params': params,
                    'body': '\n'.join(body_lines),
                    'line': i,
                })
                break

    return functions


def _extract_py_functions(source):
    """Extract function definitions from Python source."""
    functions = []
    lines = source.split('\n')

    for i, line in enumerate(lines):
        m = _PY_FUNC_RE.match(line)
        if m:
            indent = len(m.group(1))
            name = m.group(2)
            params_str = m.group(3)
            params = [p.strip().split(':')[0].split('=')[0].strip()
                      for p in params_str.split(',') if p.strip()]
            params = [p for p in params if p not in ('self', 'cls')]
            # Find body end by indentation
            body_lines = [line]
            for j in range(i + 1, len(lines)):
                stripped = lines[j].strip()
                if not stripped:
                    body_lines.append(lines[j])
                    continue
                cur_indent = len(lines[j]) - len(lines[j].lstrip())
                if cur_indent <= indent:
                    break
                body_lines.append(lines[j])
            functions.append({
                'name': name,
                'params': params,
                'body': '\n'.join(body_lines),
                'line': i,
            })

    return functions


# ---------------------------------------------------------------------------
# Public API — functions expected by tests/cross_file_taint_test.py
# ---------------------------------------------------------------------------

def extract_dangerous_functions_regex(source, language):
    """Identify functions whose parameters flow to dangerous sinks.

    Returns a list of dicts:
      [{ 'function_name': str,
         'dangerous_params': [{'param_name': str, 'sink_rule_id': str}, ...] }]
    """
    lang = language.lower()
    if lang in ('javascript', 'typescript'):
        funcs = _extract_js_functions(source)
        sink_patterns = _JS_SINK_PATTERNS
    elif lang == 'python':
        funcs = _extract_py_functions(source)
        sink_patterns = _PY_SINK_PATTERNS
    else:
        return []

    results = []
    for func in funcs:
        dangerous_params = []
        body = func['body']
        param_set = set(func['params'])

        for sink_tuple in sink_patterns:
            sink_re, rule_id = sink_tuple[0], sink_tuple[1]
            line_guard = sink_tuple[2] if len(sink_tuple) > 2 else None
            for body_line in body.split('\n'):
                # If there's a line guard, the line must also match it
                if line_guard and not re.search(line_guard, body_line, re.IGNORECASE):
                    continue
                for m in re.finditer(sink_re, body_line, re.IGNORECASE):
                    var_in_sink = m.group(1)
                    # Check if the variable in the sink is one of the params
                    # or was assigned from a param
                    if var_in_sink in param_set:
                        if not any(dp['param_name'] == var_in_sink and dp['sink_rule_id'] == rule_id
                                   for dp in dangerous_params):
                            dangerous_params.append({
                                'param_name': var_in_sink,
                                'sink_rule_id': rule_id,
                            })
                    else:
                        # Check if the variable was assigned from a param
                        # e.g. const query = "SELECT ... " + param;
                        assign_re = re.compile(
                            r'(?:const|let|var|)\s*' + re.escape(var_in_sink) +
                            r'\s*=\s*(.+)',
                            re.MULTILINE
                        )
                        for am in assign_re.finditer(body):
                            rhs = am.group(1)
                            for param in func['params']:
                                if re.search(r'\b' + re.escape(param) + r'\b', rhs):
                                    if not any(dp['param_name'] == param and dp['sink_rule_id'] == rule_id
                                               for dp in dangerous_params):
                                        dangerous_params.append({
                                            'param_name': param,
                                            'sink_rule_id': rule_id,
                                        })

        if dangerous_params:
            results.append({
                'function_name': func['name'],
                'dangerous_params': dangerous_params,
            })

    return results


def _find_tainted_variables(source):
    """Find variables that receive tainted values from sources.

    Returns a dict mapping variable name -> {'source': source_expr, ...}.
    """
    tainted = {}

    for patterns in (_JS_TAINT_SOURCES, _PY_TAINT_SOURCES):
        for pat_tuple in patterns:
            pat = pat_tuple[0]
            for m in re.finditer(pat, source, re.MULTILINE):
                var_name = m.group(1)
                source_expr = m.group(2)
                tainted[var_name] = {
                    'source': source_expr,
                    'line': source[:m.start()].count('\n'),
                }

    return tainted


def _extract_import_bindings(source, language):
    """Extract import/require bindings from source code.

    Returns list of dicts:
      [{'module': str, 'names': [str], 'is_default': bool}]
    """
    bindings = []
    lang = language.lower()

    if lang in ('javascript', 'typescript'):
        # const x = require('module')  — default import
        for m in re.finditer(r'''(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
            bindings.append({
                'module': m.group(2),
                'names': [m.group(1)],
                'is_default': True,
            })
        # const { a, b } = require('module')  — named imports
        for m in re.finditer(r'''(?:const|let|var)\s+\{\s*([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(1).split(',') if n.strip()]
            bindings.append({
                'module': m.group(2),
                'names': names,
                'is_default': False,
            })
        # import x from 'module'  — ESM default
        for m in re.finditer(r'''import\s+(\w+)\s+from\s+['"]([^'"]+)['"]''', source):
            bindings.append({
                'module': m.group(2),
                'names': [m.group(1)],
                'is_default': True,
            })
        # import { a, b } from 'module'  — ESM named
        for m in re.finditer(r'''import\s+\{\s*([^}]+)\}\s*from\s+['"]([^'"]+)['"]''', source):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(1).split(',') if n.strip()]
            bindings.append({
                'module': m.group(2),
                'names': names,
                'is_default': False,
            })
    elif lang == 'python':
        for m in re.finditer(r'^from\s+(\S+)\s+import\s+(.+)', source, re.MULTILINE):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(2).split(',') if n.strip()]
            bindings.append({
                'module': m.group(1),
                'names': names,
                'is_default': False,
            })
        for m in re.finditer(r'^import\s+(\S+)(?:\s+as\s+(\w+))?', source, re.MULTILINE):
            alias = m.group(2) or m.group(1).split('.')[-1]
            bindings.append({
                'module': m.group(1),
                'names': [alias],
                'is_default': True,
            })

    return bindings


def _find_calls_to_function(source, function_name, object_name=None):
    """Find all calls to a specific function in source code.

    Returns list of dicts: [{'args': [str], 'line': int}]
    """
    calls = []

    if object_name:
        pattern = re.escape(object_name) + r'\.' + re.escape(function_name) + r'\s*\(([^)]*)\)'
    else:
        pattern = r'(?<!\w\.)' + re.escape(function_name) + r'\s*\(([^)]*)\)'

    for m in re.finditer(pattern, source):
        args_str = m.group(1).strip()
        args = [a.strip() for a in args_str.split(',') if a.strip()] if args_str else []
        line = source[:m.start()].count('\n')
        calls.append({
            'args': args,
            'line': line,
        })

    return calls


def build_export_summaries(file_paths, sources_dict):
    """Build dangerous function summaries for each file.

    Args:
        file_paths: list of file paths
        sources_dict: dict mapping absolute path -> source code string

    Returns dict mapping absolute path -> list of dangerous function summaries.
    """
    summaries = {}

    for file_path in file_paths:
        abs_path = os.path.abspath(file_path)
        source = sources_dict.get(abs_path)
        if not source:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source = f.read()
            except (OSError, IOError):
                continue

        lang = detect_language(file_path)
        if lang == 'unknown':
            continue

        dangerous = extract_dangerous_functions_regex(source, lang)
        if dangerous:
            summaries[abs_path] = dangerous

    return summaries


def cross_file_taint_match(source_file, sink_file, tainted_var, callee_name,
                           dangerous_param, taint_source):
    """Build a cross-file-taint finding.

    Returns a finding dict with ruleId 'cross-file-taint' and full metadata.
    """
    return {
        'ruleId': 'cross-file-taint',
        'severity': 'error',
        'message': (
            f"Tainted data from {taint_source} in "
            f"'{os.path.basename(source_file)}' flows to "
            f"'{callee_name}({dangerous_param})' which reaches a "
            f"dangerous sink in '{os.path.basename(sink_file)}'"
        ),
        'file': source_file,
        'line': 0,
        'column': 0,
        'metadata': {
            'source_file': source_file,
            'sink_file': sink_file,
            'taint_path': [
                f"{os.path.basename(source_file)}: {tainted_var} = {taint_source}",
                f"{os.path.basename(source_file)}: {callee_name}({tainted_var})",
                f"{os.path.basename(sink_file)}: {callee_name}({dangerous_param}) -> sink",
            ],
            'tainted_variable': tainted_var,
            'callee_function': callee_name,
            'dangerous_param': dangerous_param,
        }
    }


# ---------------------------------------------------------------------------
# Existing helpers (unchanged)
# ---------------------------------------------------------------------------

def extract_js_imports(source):
    """Extract import/require statements from JavaScript/TypeScript."""
    imports = []
    # require('...')
    for m in re.finditer(r'''require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
        imports.append(m.group(1))
    # import ... from '...'
    for m in re.finditer(r'''from\s+['"]([^'"]+)['"]''', source):
        imports.append(m.group(1))
    # import '...'
    for m in re.finditer(r'''import\s+['"]([^'"]+)['"]''', source):
        imports.append(m.group(1))
    return imports


def extract_py_imports(source):
    """Extract import statements from Python."""
    imports = []
    # import module
    for m in re.finditer(r'^import\s+(\S+)', source, re.MULTILINE):
        imports.append(m.group(1).split('.')[0])
    # from module import ...
    for m in re.finditer(r'^from\s+(\S+)\s+import', source, re.MULTILINE):
        imports.append(m.group(1).split('.')[0])
    return imports


def detect_language(file_path):
    """Detect language from file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    lang_map = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
        '.tsx': 'typescript', '.jsx': 'javascript',
    }
    return lang_map.get(ext, 'unknown')


def resolve_local_import(module, base_dir, lang):
    """Resolve a relative/local import to an actual file path."""
    if lang in ('javascript', 'typescript'):
        # Only resolve relative imports
        if not module.startswith('.'):
            return None
        # Try common extensions
        candidates = [
            module,
            module + '.js', module + '.ts', module + '.tsx', module + '.jsx',
            os.path.join(module, 'index.js'), os.path.join(module, 'index.ts'),
        ]
        for candidate in candidates:
            full = os.path.normpath(os.path.join(base_dir, candidate))
            if os.path.isfile(full):
                return full
    elif lang == 'python':
        # Only resolve relative imports (starting with .)
        if module.startswith('.'):
            rel = module.lstrip('.')
            candidates = [
                os.path.join(base_dir, rel.replace('.', os.sep) + '.py'),
                os.path.join(base_dir, rel.replace('.', os.sep), '__init__.py'),
            ]
            for candidate in candidates:
                if os.path.isfile(candidate):
                    return candidate
        # Also check if the module name matches a sibling file
        sibling = os.path.join(base_dir, module + '.py')
        if os.path.isfile(sibling):
            return sibling
    return None


def extract_exports(source, lang):
    """Extract exported function/class names."""
    exports = []
    if lang in ('javascript', 'typescript'):
        for m in re.finditer(r'export\s+(?:function|class|const|let|var)\s+(\w+)', source):
            exports.append(m.group(1))
        for m in re.finditer(r'module\.exports\s*=', source):
            exports.append('default')
    elif lang == 'python':
        for m in re.finditer(r'^(?:def|class)\s+(\w+)', source, re.MULTILINE):
            exports.append(m.group(1))
    return exports


def build_import_graph(file_paths):
    """Build import graph: {file -> [{module, resolved_path, line}]}."""
    graph = {}
    file_set = set(os.path.abspath(f) for f in file_paths)

    for file_path in file_paths:
        abs_path = os.path.abspath(file_path)
        lang = detect_language(file_path)
        if lang == 'unknown':
            continue

        try:
            source = open(file_path, 'r', encoding='utf-8', errors='ignore').read()
        except (OSError, IOError):
            continue

        if lang in ('javascript', 'typescript'):
            modules = extract_js_imports(source)
        elif lang == 'python':
            modules = extract_py_imports(source)
        else:
            continue

        base_dir = os.path.dirname(abs_path)
        edges = []
        for mod in modules:
            resolved = resolve_local_import(mod, base_dir, lang)
            if resolved:
                resolved_abs = os.path.abspath(resolved)
                if resolved_abs in file_set and resolved_abs != abs_path:
                    edges.append({
                        'module': mod,
                        'resolved_path': resolved_abs,
                    })

        graph[abs_path] = edges

    return graph


def cross_file_analyze(file_paths):
    """Run cross-file taint analysis.

    1. Analyze each file independently
    2. Build import graph
    3. For each file importing from another file with ERROR-severity findings,
       add a cross-file-taint-warning (backward compat)
    4. Build export summaries and perform parameter-aware cross-file taint
       matching to produce cross-file-taint findings.
    """
    # Analyze each file
    file_findings = {}
    all_findings = []
    sources_dict = {}

    for file_path in file_paths:
        try:
            results = analyze_file(file_path)
            if isinstance(results, list):
                file_findings[os.path.abspath(file_path)] = results
                for finding in results:
                    finding['file'] = file_path
                all_findings.extend(results)
        except Exception:
            continue

        # Cache source code for later
        try:
            abs_path = os.path.abspath(file_path)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sources_dict[abs_path] = f.read()
        except (OSError, IOError):
            pass

    # Build import graph
    graph = build_import_graph(file_paths)

    # --- Backward-compatible shallow warnings ---
    cross_file_warnings = []
    for file_path, edges in graph.items():
        for edge in edges:
            imported_path = edge['resolved_path']
            imported_findings = file_findings.get(imported_path, [])

            # Check for ERROR-severity findings in imported file
            error_findings = [f for f in imported_findings if f.get('severity') == 'error']
            if error_findings:
                warning = {
                    'ruleId': 'cross-file-taint-warning',
                    'severity': 'warning',
                    'message': f"Imports from '{os.path.basename(imported_path)}' which has {len(error_findings)} critical finding(s): {', '.join(set(f.get('ruleId', 'unknown') for f in error_findings))}",
                    'file': file_path,
                    'line': 0,
                    'metadata': {
                        'imported_file': imported_path,
                        'imported_findings_count': len(error_findings),
                    }
                }
                cross_file_warnings.append(warning)

    # --- Parameter-aware cross-file taint matching ---
    export_summaries = build_export_summaries(file_paths, sources_dict)
    cross_file_taint_findings = []

    for source_file, edges in graph.items():
        source_code = sources_dict.get(source_file, '')
        if not source_code:
            continue

        lang = detect_language(source_file)
        if lang == 'unknown':
            continue

        tainted_vars = _find_tainted_variables(source_code)
        import_bindings = _extract_import_bindings(source_code, lang)

        for edge in edges:
            sink_file = edge['resolved_path']
            sink_summaries = export_summaries.get(sink_file, [])
            if not sink_summaries:
                continue

            # Find the import binding for this module
            module_name = edge['module']
            relevant_bindings = [b for b in import_bindings if b['module'] == module_name]

            for summary in sink_summaries:
                func_name = summary['function_name']

                for binding in relevant_bindings:
                    if binding['is_default']:
                        # Default import: db = require('./lib/db')
                        # Calls look like: db.getUserById(arg)
                        obj_name = binding['names'][0] if binding['names'] else None
                        if obj_name:
                            calls = _find_calls_to_function(source_code, func_name, obj_name)
                        else:
                            calls = []
                    else:
                        # Named import: { getUserById } = require('./lib/db')
                        if func_name in binding['names']:
                            calls = _find_calls_to_function(source_code, func_name)
                        else:
                            calls = []

                    for call in calls:
                        for dp in summary['dangerous_params']:
                            param_name = dp['param_name']
                            # Find which arg position this param is
                            try:
                                param_idx = [p.strip() for p in _get_func_params(
                                    sink_summaries, func_name
                                )].index(param_name)
                            except (ValueError, IndexError):
                                param_idx = 0

                            if param_idx < len(call['args']):
                                arg_name = call['args'][param_idx]
                                if arg_name in tainted_vars:
                                    taint_source = tainted_vars[arg_name]['source']
                                    finding = cross_file_taint_match(
                                        source_file, sink_file,
                                        arg_name, func_name,
                                        param_name, taint_source
                                    )
                                    finding['line'] = call.get('line', 0)
                                    cross_file_taint_findings.append(finding)

    # Combine: per-file findings + shallow warnings + cross-file taint findings
    combined = all_findings + cross_file_warnings + cross_file_taint_findings
    return combined


def _get_func_params(summaries, func_name):
    """Get parameter names for a function from its summary list."""
    # Extract params from the function body in the summary
    for s in summaries:
        if s['function_name'] == func_name:
            return [dp['param_name'] for dp in s['dangerous_params']]
    return []


def main():
    """CLI entry point. Accepts file paths as arguments, outputs JSON."""
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: cross_file_analyzer.py file1 file2 ...'}))
        sys.exit(1)

    file_paths = sys.argv[1:]
    # Filter to existing files
    file_paths = [f for f in file_paths if os.path.isfile(f)]

    if not file_paths:
        print(json.dumps({'error': 'No valid files provided'}))
        sys.exit(1)

    results = cross_file_analyze(file_paths)
    print(json.dumps(results))


if __name__ == '__main__':
    main()
