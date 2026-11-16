"""
Security Analyzer - AST-Based with Regex Fallback

Uses tree-sitter AST analysis when available, falls back to regex
pattern matching when tree-sitter is not installed. This ensures
the analyzer works out-of-the-box with `npx` (regex mode) and
provides enhanced detection when dependencies are installed.
"""

import sys
import warnings

# Suppress regex deprecation warnings for patterns with inline flags
warnings.filterwarnings('ignore', category=DeprecationWarning)
import fnmatch
import json
import os
import re
import argparse
from typing import List, Dict, Any

# Add the directory containing this script to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import AST engine
try:
    from ast_parser import ASTParser, HAS_TREE_SITTER
    from generic_ast import convert_tree
    from pattern_matcher import RuleEngine
    from regex_fallback import apply_regex_fallback
    HAS_AST_ENGINE = HAS_TREE_SITTER
except ImportError:
    HAS_AST_ENGINE = False

# Try to import Semgrep loader and taint analyzer
try:
    from semgrep_loader import load_rules, get_loader
    HAS_SEMGREP_LOADER = True
except ImportError:
    HAS_SEMGREP_LOADER = False

try:
    from taint_analyzer import TaintAnalyzer
    HAS_TAINT_ANALYZER = True
except ImportError:
    HAS_TAINT_ANALYZER = False

try:
    from python_taint_fallback import analyze_python_taint
    HAS_PYTHON_TAINT_FALLBACK = True
except ImportError:
    HAS_PYTHON_TAINT_FALLBACK = False

# Semantic analyzer flag (JavaScript-based, optional)
HAS_SEMANTIC_ANALYZER = True  # Implemented in src/semantic-analyzer.js

# Import the original regex-based rules (always available)
from rules import get_rules_for_language

# File extension to language mapping
EXTENSION_MAP = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
    '.tsx': 'typescript', '.jsx': 'javascript', '.java': 'java',
    '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp',
    '.rs': 'rust', '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
    '.sql': 'sql', '.dockerfile': 'dockerfile',
    '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
    '.tf': 'terraform', '.hcl': 'terraform',
    '.txt': 'generic', '.md': 'generic', '.prompt': 'generic',
    '.jinja': 'generic', '.jinja2': 'generic', '.j2': 'generic',
}


def detect_language(file_path):
    """Detect the programming language from file extension or name."""
    basename = os.path.basename(file_path).lower()
    if basename == 'dockerfile' or basename.startswith('dockerfile.'):
        return 'dockerfile'
    _, ext = os.path.splitext(file_path.lower())
    return EXTENSION_MAP.get(ext, 'generic')


def _matches_path_filter(file_path, rule):
    """Check if file_path matches a rule's paths.include/exclude filter.

    Returns True if the rule should be applied to this file.
    Rules without paths metadata apply to all files.
    """
    paths = rule.metadata.get('paths') if hasattr(rule, 'metadata') else None
    if not paths or not isinstance(paths, dict):
        return True

    basename = os.path.basename(file_path)

    # If include patterns exist, file must match at least one
    include = paths.get('include')
    if include and isinstance(include, list):
        if not any(fnmatch.fnmatch(basename, p) or fnmatch.fnmatch(file_path, p) for p in include):
            return False

    # If exclude patterns exist, file must NOT match any
    exclude = paths.get('exclude')
    if exclude and isinstance(exclude, list):
        if any(fnmatch.fnmatch(basename, p) or fnmatch.fnmatch(file_path, p) for p in exclude):
            return False

    return True


def analyze_file_regex(file_path):
    """Original regex-based analysis (fallback when tree-sitter unavailable)."""
    issues = []
    try:
        language = detect_language(file_path)
        all_rules = get_rules_for_language(language, file_path)
        # Filter out rules whose paths.include/exclude don't match this file
        rules = {}
        basename = os.path.basename(file_path)
        for rid, r in all_rules.items():
            rule_paths = r.get('metadata', {}).get('paths')
            if rule_paths and isinstance(rule_paths, dict):
                include = rule_paths.get('include')
                if include and isinstance(include, list):
                    if not any(fnmatch.fnmatch(basename, p) or fnmatch.fnmatch(file_path, p) for p in include):
                        continue
                exclude = rule_paths.get('exclude')
                if exclude and isinstance(exclude, list):
                    if any(fnmatch.fnmatch(basename, p) or fnmatch.fnmatch(file_path, p) for p in exclude):
                        continue
            rules[rid] = r
        print(f"[REGEX] Language: {language}, rules loaded: {len(rules)}", file=sys.stderr)
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line_index, original_line in enumerate(lines):
            line = original_line.strip()
            if not line or line.startswith('#') or line.startswith('//') or line.startswith('*'):
                continue
            for rule_id, rule in rules.items():
                for pattern in rule['patterns']:
                    try:
                        for match in re.finditer(pattern, line, re.IGNORECASE):
                            col_offset = len(original_line) - len(original_line.lstrip())
                            issues.append({
                                'ruleId': rule['id'],
                                'message': f"[{rule['name']}] {rule['message']}",
                                'line': line_index,
                                'column': match.start() + col_offset,
                                'length': match.end() - match.start(),
                                'severity': rule['severity'],
                                'confidence': rule.get('metadata', {}).get('confidence', 'MEDIUM'),
                                'metadata': rule.get('metadata', {}),
                                'engine': 'regex'
                            })
                    except re.error:
                        continue
    except Exception as e:
        return {'error': str(e)}

    # Also apply regex_fallback for broader coverage (C, Rust, C# etc.)
    try:
        from regex_fallback import apply_regex_fallback
        with open(file_path, 'r', errors='replace') as f:
            source = f.read()
        fallback_issues = apply_regex_fallback(source, language, file_path)
        for issue in fallback_issues:
            issue['engine'] = 'regex-fallback'
        issues.extend(fallback_issues)
    except ImportError:
        source = None

    # Python taint fallback using stdlib ast (no tree-sitter required)
    if language == 'python' and HAS_PYTHON_TAINT_FALLBACK:
        try:
            if source is None:
                with open(file_path, 'r', errors='replace') as f:
                    source = f.read()
            taint_issues = analyze_python_taint(source, file_path)
            for issue in taint_issues:
                issue.setdefault('engine', 'taint')
                issue.get('metadata', {}).setdefault('analysis_mode', 'regex-fallback')
            issues.extend(taint_issues)
            print(f"[REGEX] Python taint fallback: {len(taint_issues)} finding(s)", file=sys.stderr)
        except Exception as e:
            print(f"[REGEX] Python taint fallback error: {e}", file=sys.stderr)

    seen = set()
    unique = []
    for issue in issues:
        key = (issue['ruleId'], issue['line'], issue['column'])
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


def analyze_file_ast(file_path):
    """AST-based analysis using tree-sitter."""
    try:
        parser = ASTParser()
        engine = RuleEngine()

        # Load rules
        rules = []
        taint_rules = []
        if HAS_SEMGREP_LOADER:
            supported = ['python', 'javascript', 'typescript', 'java', 'go',
                         'ruby', 'php', 'c', 'rust', 'csharp', 'generic']
            rules = load_rules(supported)
            loader = get_loader()
            taint_rules = loader.get_taint_rules()

        parse_result = parser.parse_file(file_path)
        if not parse_result.success:
            print(f"[AST] Parse failed for {file_path}, falling back to regex", file=sys.stderr)
            return analyze_file_regex(file_path)

        print(f"[AST] Engine active, language: {parse_result.language}, "
              f"rules loaded: {len(rules)}, taint rules: {len(taint_rules)}", file=sys.stderr)

        ast = convert_tree(parse_result.tree, parse_result.language, parse_result.source_bytes)

        # Only apply security-relevant rules; exclude non-security and framework-config rules
        # that produce false positives due to broad pattern matching
        SECURITY_CATEGORIES = {'security', 'prompt-injection', 'prompt-injection-content',
                               'prompt-injection-context', 'prompt-injection-delimiter',
                               'prompt-injection-encoded', 'prompt-injection-extraction',
                               'prompt-injection-jailbreak', 'prompt-injection-multi-turn',
                               'prompt-injection-output', 'prompt-injection-privilege', 'unknown'}
        NOISY_RULES = {
            'avoid_hardcoded_config_DEBUG', 'avoid_hardcoded_config_ENV',
            'avoid_hardcoded_config_SECRET_KEY', 'avoid_hardcoded_config_TESTING',
            'flask-wtf-csrf-disabled', 'context-autoescape-off',
        }
        applicable_rules = [
            r for r in rules
            if (parse_result.language in r.languages or 'generic' in r.languages)
            and r.metadata.get('category', 'unknown') in SECURITY_CATEGORIES
            and r.id not in NOISY_RULES
            and _matches_path_filter(file_path, r)
        ]

        findings = engine.apply_rules(applicable_rules, ast)

        # Taint analysis
        taint_findings = []
        if HAS_TAINT_ANALYZER and taint_rules:
            taint = TaintAnalyzer()
            applicable_taint = [
                r for r in taint_rules
                if parse_result.language in r.languages or 'generic' in r.languages
            ]
            taint_findings = taint.analyze(ast, applicable_taint)
            print(f"[TAINT] Taint rules: {len(applicable_taint)}, findings: {len(taint_findings)}", file=sys.stderr)
            findings.extend(taint_findings)

        issues = []
        for f in findings:
            length = f.end_column - f.column if f.line == f.end_line else len(f.text)
            is_taint = f in taint_findings
            issues.append({
                'ruleId': f.rule_id,
                'message': f"[{f.rule_name}] {f.message}",
                'line': f.line - 1,  # Convert to 0-indexed for compatibility
                'column': f.column,
                'length': length,
                'severity': f.severity,
                'confidence': f.metadata.get('confidence', getattr(f, 'confidence', 'MEDIUM')),
                'metadata': f.metadata,
                'engine': 'taint' if is_taint else 'ast',
            })

        # Regex fallback for coverage gaps
        source = parse_result.source_bytes.decode('utf-8', errors='replace')
        regex_fallback_issues = apply_regex_fallback(source, parse_result.language, file_path)
        for issue in regex_fallback_issues:
            issue['engine'] = 'regex-fallback'
        issues.extend(regex_fallback_issues)

        ast_count = sum(1 for i in issues if i.get('engine') == 'ast')
        taint_count = sum(1 for i in issues if i.get('engine') == 'taint')
        fallback_count = sum(1 for i in issues if i.get('engine') == 'regex-fallback')
        print(f"[AST] Findings: {ast_count} ast + {taint_count} taint + {fallback_count} regex-fallback", file=sys.stderr)

        seen = set()
        unique = []
        for issue in issues:
            key = (issue['ruleId'], issue['line'], issue['column'])
            if key not in seen:
                seen.add(key)
                unique.append(issue)
        return unique

    except Exception as e:
        print(f"[AST] Error, falling back to regex: {e}", file=sys.stderr)
        return analyze_file_regex(file_path)


def analyze_file(file_path):
    """Analyze a file — uses AST engine if available, regex otherwise."""
    if HAS_AST_ENGINE:
        return analyze_file_ast(file_path)
    return analyze_file_regex(file_path)


def main():
    parser = argparse.ArgumentParser(description='Security Analyzer - AST-based with regex fallback')
    parser.add_argument('file_path', help='Path to the file to analyze')
    parser.add_argument('--engine', choices=['auto', 'ast', 'regex'], default='auto',
                        help='Analysis engine: auto (default), ast (tree-sitter only), regex (regex only)')
    args = parser.parse_args()

    file_path = args.file_path
    if not os.path.exists(file_path):
        print(json.dumps({'error': f'File not found: {file_path}'}))
        sys.exit(1)

    engine = args.engine

    if engine == 'regex':
        results = analyze_file_regex(file_path)
    elif engine == 'ast':
        if not HAS_AST_ENGINE:
            print(json.dumps({'error': 'AST engine requested but tree-sitter is not available. Install dependencies: python3 -m pip install -r requirements.txt'}))
            sys.exit(1)
        results = analyze_file_ast(file_path)
    else:
        # auto: use AST if available, otherwise regex
        results = analyze_file(file_path)

    print(json.dumps(results))


if __name__ == '__main__':
    main()
