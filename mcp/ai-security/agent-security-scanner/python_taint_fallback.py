"""Lightweight Python taint analysis without tree-sitter.

Uses the stdlib ``ast`` module so Python taint findings are still available
when the tree-sitter engine is not installed. The implementation is purposely
conservative and targets the high-signal flows exercised by the test suite:

- Flask/Django-style request sources
- input()-derived taint
- intra-procedural propagation through assignments and expressions
- inter-procedural propagation through simple function summaries
- internal sinks reached inside callees
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


SUMMARY_SOURCE = -1
MAX_INTERPROCEDURAL_FUNCTIONS = 500

SOURCE_CALLS = {
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.view_args.get",
    "request.json.get",
    "flask.request.args.get",
    "flask.request.form.get",
    "flask.request.values.get",
    "flask.request.cookies.get",
    "flask.request.headers.get",
    "flask.request.view_args.get",
    "flask.request.json.get",
    "input",
}

SOURCE_ATTRIBUTES = {
    "request.args",
    "request.form",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.view_args",
    "request.json",
    "flask.request.args",
    "flask.request.form",
    "flask.request.values",
    "flask.request.cookies",
    "flask.request.headers",
    "flask.request.view_args",
    "flask.request.json",
}

SANITIZER_CALLS = {
    "shlex.quote",
    "quote",
    "html.escape",
    "markupsafe.escape",
    "urllib.parse.quote",
}


@dataclass
class TaintInfo:
    source_pattern: str
    source_line: int
    propagation_path: List[str] = field(default_factory=list)


@dataclass
class InternalSink:
    rule_id: str
    message: str
    param_indices: Set[int]
    line: int


@dataclass
class FunctionSummary:
    name: str
    params: List[str]
    returns_taint_from: Set[int] = field(default_factory=set)
    returns_source: bool = False
    source_pattern: Optional[str] = None
    internal_sinks: List[InternalSink] = field(default_factory=list)
    has_sanitizer: bool = False
    line: int = 0


def _get_qualified_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _source_pattern(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Call):
        qname = _get_qualified_name(node.func)
        if qname in SOURCE_CALLS:
            return qname
    if isinstance(node, ast.Subscript):
        qname = _get_qualified_name(node.value)
        if qname in SOURCE_ATTRIBUTES:
            return qname
    if isinstance(node, ast.Attribute):
        qname = _get_qualified_name(node)
        if qname in SOURCE_ATTRIBUTES:
            return qname
    return None


def _is_sanitizer_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _get_qualified_name(node.func) in SANITIZER_CALLS


def _extract_target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
        return names
    return []


def _merge_dependency_maps(*maps: Dict[str, Set[int]]) -> Dict[str, Set[int]]:
    merged: Dict[str, Set[int]] = {}
    for mapping in maps:
        for key, value in mapping.items():
            merged[key] = merged.get(key, set()) | set(value)
    return merged


def _merge_taint_envs(*envs: Dict[str, TaintInfo]) -> Dict[str, TaintInfo]:
    merged: Dict[str, TaintInfo] = {}
    for env in envs:
        for key, value in env.items():
            if key not in merged:
                merged[key] = value
    return merged


def _node_column(node: ast.AST) -> int:
    return getattr(node, "col_offset", 0)


def _find_first_taint(node: ast.AST, env: Dict[str, TaintInfo]) -> Optional[Tuple[str, TaintInfo]]:
    if isinstance(node, ast.Name) and node.id in env:
        return node.id, env[node.id]
    if isinstance(node, ast.Attribute):
        return _find_first_taint(node.value, env)
    if isinstance(node, ast.Subscript):
        found = _find_first_taint(node.value, env)
        if found:
            return found
        return _find_first_taint(node.slice, env)
    for child in ast.iter_child_nodes(node):
        found = _find_first_taint(child, env)
        if found:
            return found
    return None


def _match_sink(node: ast.Call) -> Optional[Tuple[str, str, List[ast.AST]]]:
    qname = _get_qualified_name(node.func)
    if not qname:
        return None

    if qname.endswith(".execute") and node.args:
        return (
            "sql-injection",
            "User-controlled data flows to SQL execution.",
            [node.args[0]],
        )

    if qname == "os.system" and node.args:
        return (
            "command-injection",
            "User-controlled data flows to os.system().",
            [node.args[0]],
        )

    if qname.startswith("subprocess.") and node.args:
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if shell_true:
            return (
                "command-injection",
                "User-controlled data flows to subprocess with shell=True.",
                [node.args[0]],
            )

    if qname == "open" and node.args:
        return (
            "path-traversal",
            "User-controlled data flows to file open().",
            [node.args[0]],
        )

    if qname.endswith("render_template_string") and node.args:
        return (
            "xss",
            "User-controlled data flows to render_template_string().",
            [node.args[0]],
        )

    if qname in {"eval", "exec"} and node.args:
        return (
            "code-injection",
            "User-controlled data flows to dynamic code execution.",
            [node.args[0]],
        )

    return None


class _SummaryBuilder:
    def __init__(self, tree: ast.AST):
        self.functions: Dict[str, ast.AST] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node

    def build(self) -> Dict[str, FunctionSummary]:
        if len(self.functions) > MAX_INTERPROCEDURAL_FUNCTIONS:
            return {}

        summaries = {
            name: FunctionSummary(
                name=name,
                params=self._params(func),
                line=getattr(func, "lineno", 0),
            )
            for name, func in self.functions.items()
        }

        for _ in range(8):
            changed = False
            for name, func in self.functions.items():
                updated = self._compute_summary(func, summaries)
                if updated != summaries[name]:
                    summaries[name] = updated
                    changed = True
            if not changed:
                break

        return summaries

    @staticmethod
    def _params(func: ast.AST) -> List[str]:
        params: List[str] = []
        for arg in getattr(func.args, "args", []):
            if arg.arg not in {"self", "cls"}:
                params.append(arg.arg)
        return params

    def _compute_summary(
        self,
        func: ast.AST,
        summaries: Dict[str, FunctionSummary],
    ) -> FunctionSummary:
        params = self._params(func)
        env: Dict[str, Set[int]] = {name: {idx} for idx, name in enumerate(params)}
        returns_taint_from: Set[int] = set()
        returns_source = False
        source_pattern: Optional[str] = None
        internal_sinks: List[InternalSink] = []
        has_sanitizer = False

        def expr_deps(node: Optional[ast.AST], local_env: Dict[str, Set[int]]) -> Set[int]:
            nonlocal has_sanitizer
            if node is None:
                return set()

            pattern = _source_pattern(node)
            if pattern:
                return {SUMMARY_SOURCE}

            if isinstance(node, ast.Name):
                return set(local_env.get(node.id, set()))

            if isinstance(node, ast.Attribute):
                return expr_deps(node.value, local_env)

            if isinstance(node, ast.Subscript):
                return expr_deps(node.value, local_env) | expr_deps(node.slice, local_env)

            if isinstance(node, ast.Call):
                if _is_sanitizer_call(node):
                    has_sanitizer = True
                    return set()

                qname = _get_qualified_name(node.func)
                if qname and qname in summaries:
                    summary = summaries[qname]
                    deps: Set[int] = set()
                    if summary.returns_source:
                        deps.add(SUMMARY_SOURCE)
                    for idx in summary.returns_taint_from:
                        if idx < len(node.args):
                            deps |= expr_deps(node.args[idx], local_env)
                    if summary.has_sanitizer and not deps:
                        has_sanitizer = True
                    return deps

                deps = expr_deps(getattr(node.func, "value", None), local_env)
                for arg in node.args:
                    deps |= expr_deps(arg, local_env)
                for kw in node.keywords:
                    deps |= expr_deps(kw.value, local_env)
                return deps

            deps: Set[int] = set()
            for child in ast.iter_child_nodes(node):
                deps |= expr_deps(child, local_env)
            return deps

        def process_statements(
            statements: Iterable[ast.stmt],
            local_env: Dict[str, Set[int]],
        ) -> Dict[str, Set[int]]:
            nonlocal returns_source, source_pattern, internal_sinks, returns_taint_from

            for stmt in statements:
                if isinstance(stmt, ast.Assign):
                    deps = expr_deps(stmt.value, local_env)
                    for target in stmt.targets:
                        for name in _extract_target_names(target):
                            local_env[name] = set(deps)

                elif isinstance(stmt, ast.AnnAssign):
                    deps = expr_deps(stmt.value, local_env)
                    for name in _extract_target_names(stmt.target):
                        local_env[name] = set(deps)

                elif isinstance(stmt, ast.AugAssign):
                    deps = expr_deps(stmt.value, local_env) | expr_deps(stmt.target, local_env)
                    for name in _extract_target_names(stmt.target):
                        local_env[name] = set(deps)

                elif isinstance(stmt, ast.Return):
                    deps = expr_deps(stmt.value, local_env)
                    if SUMMARY_SOURCE in deps:
                        returns_source = True
                        source_pattern = source_pattern or _source_pattern(stmt.value) or "request.args.get"
                    returns_taint_from |= {d for d in deps if d != SUMMARY_SOURCE}

                elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    sink = _match_sink(stmt.value)
                    if sink:
                        rule_id, message, relevant_args = sink
                        param_indices: Set[int] = set()
                        for arg in relevant_args:
                            deps = expr_deps(arg, local_env)
                            param_indices |= {d for d in deps if d != SUMMARY_SOURCE}
                        if param_indices:
                            internal_sinks.append(
                                InternalSink(
                                    rule_id=rule_id,
                                    message=message,
                                    param_indices=param_indices,
                                    line=getattr(stmt.value, "lineno", getattr(stmt, "lineno", 1)),
                                )
                            )

                    qname = _get_qualified_name(stmt.value.func)
                    if qname and qname in summaries:
                        summary = summaries[qname]
                        for isink in summary.internal_sinks:
                            param_indices: Set[int] = set()
                            for idx in isink.param_indices:
                                if idx < len(stmt.value.args):
                                    deps = expr_deps(stmt.value.args[idx], local_env)
                                    param_indices |= {d for d in deps if d != SUMMARY_SOURCE}
                            if param_indices:
                                internal_sinks.append(
                                    InternalSink(
                                        rule_id=isink.rule_id,
                                        message=isink.message,
                                        param_indices=param_indices,
                                        line=getattr(stmt.value, "lineno", getattr(stmt, "lineno", 1)),
                                    )
                                )

                elif isinstance(stmt, ast.If):
                    before = dict(local_env)
                    body_env = process_statements(stmt.body, dict(local_env))
                    else_env = process_statements(stmt.orelse, dict(local_env))
                    local_env = _merge_dependency_maps(before, body_env, else_env)

                elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                    body_env = process_statements(stmt.body, dict(local_env))
                    else_env = process_statements(getattr(stmt, "orelse", []), dict(local_env))
                    local_env = _merge_dependency_maps(local_env, body_env, else_env)

                elif isinstance(stmt, ast.Try):
                    branch_envs = [dict(local_env)]
                    branch_envs.append(process_statements(stmt.body, dict(local_env)))
                    for handler in stmt.handlers:
                        branch_envs.append(process_statements(handler.body, dict(local_env)))
                    branch_envs.append(process_statements(stmt.orelse, dict(local_env)))
                    branch_envs.append(process_statements(stmt.finalbody, dict(local_env)))
                    local_env = _merge_dependency_maps(*branch_envs)

            return local_env

        process_statements(getattr(func, "body", []), env)
        return FunctionSummary(
            name=func.name,
            params=params,
            returns_taint_from=returns_taint_from,
            returns_source=returns_source,
            source_pattern=source_pattern,
            internal_sinks=internal_sinks,
            has_sanitizer=has_sanitizer,
            line=getattr(func, "lineno", 0),
        )


class _PythonTaintAnalyzer:
    def __init__(self, source: str, file_path: str):
        self.source = source
        self.file_path = file_path
        self.tree = ast.parse(source, filename=file_path)
        self.summaries = _SummaryBuilder(self.tree).build()

    def analyze(self) -> List[dict]:
        findings: List[dict] = []
        findings.extend(self._analyze_statements(getattr(self.tree, "body", []), {}))

        for node in getattr(self.tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._analyze_statements(node.body, {}))

        unique: List[dict] = []
        seen = set()
        for finding in findings:
            key = (finding["ruleId"], finding["line"], finding["column"], finding["metadata"].get("tainted_variable"))
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    def _analyze_statements(
        self,
        statements: Iterable[ast.stmt],
        env: Dict[str, TaintInfo],
    ) -> List[dict]:
        findings: List[dict] = []
        local_env = dict(env)

        for stmt in statements:
            if isinstance(stmt, ast.Assign):
                taint = self._expr_taint(stmt.value, local_env)
                for target in stmt.targets:
                    for name in _extract_target_names(target):
                        if taint:
                            local_env[name] = TaintInfo(
                                source_pattern=taint.source_pattern,
                                source_line=taint.source_line,
                                propagation_path=taint.propagation_path
                                + [f"Line {getattr(stmt, 'lineno', 1)}: {name} = ..."],
                            )
                        elif name in local_env:
                            del local_env[name]
                findings.extend(self._statement_findings(stmt, local_env))

            elif isinstance(stmt, ast.AnnAssign):
                taint = self._expr_taint(stmt.value, local_env)
                for name in _extract_target_names(stmt.target):
                    if taint:
                        local_env[name] = TaintInfo(
                            source_pattern=taint.source_pattern,
                            source_line=taint.source_line,
                            propagation_path=taint.propagation_path
                            + [f"Line {getattr(stmt, 'lineno', 1)}: {name} = ..."],
                        )
                    elif name in local_env:
                        del local_env[name]
                findings.extend(self._statement_findings(stmt, local_env))

            elif isinstance(stmt, ast.AugAssign):
                taint = self._expr_taint(stmt.value, local_env) or self._expr_taint(stmt.target, local_env)
                for name in _extract_target_names(stmt.target):
                    if taint:
                        local_env[name] = TaintInfo(
                            source_pattern=taint.source_pattern,
                            source_line=taint.source_line,
                            propagation_path=taint.propagation_path
                            + [f"Line {getattr(stmt, 'lineno', 1)}: {name} = ..."],
                        )
                findings.extend(self._statement_findings(stmt, local_env))

            elif isinstance(stmt, ast.If):
                body_findings = self._analyze_statements(stmt.body, dict(local_env))
                else_findings = self._analyze_statements(stmt.orelse, dict(local_env))
                findings.extend(body_findings)
                findings.extend(else_findings)
                local_env = _merge_taint_envs(local_env)

            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                findings.extend(self._statement_findings(stmt, local_env))
                findings.extend(self._analyze_statements(stmt.body, dict(local_env)))
                findings.extend(self._analyze_statements(getattr(stmt, "orelse", []), dict(local_env)))

            elif isinstance(stmt, ast.Try):
                findings.extend(self._analyze_statements(stmt.body, dict(local_env)))
                for handler in stmt.handlers:
                    findings.extend(self._analyze_statements(handler.body, dict(local_env)))
                findings.extend(self._analyze_statements(stmt.orelse, dict(local_env)))
                findings.extend(self._analyze_statements(stmt.finalbody, dict(local_env)))

            else:
                findings.extend(self._statement_findings(stmt, local_env))

        return findings

    def _expr_taint(self, node: Optional[ast.AST], env: Dict[str, TaintInfo]) -> Optional[TaintInfo]:
        if node is None:
            return None

        pattern = _source_pattern(node)
        if pattern:
            return TaintInfo(
                source_pattern=pattern,
                source_line=getattr(node, "lineno", 1),
                propagation_path=[f"Source: {pattern}"],
            )

        if isinstance(node, ast.Name):
            return env.get(node.id)

        if isinstance(node, ast.Attribute):
            return self._expr_taint(node.value, env)

        if isinstance(node, ast.Subscript):
            return self._expr_taint(node.value, env) or self._expr_taint(node.slice, env)

        if isinstance(node, ast.Call):
            if _is_sanitizer_call(node):
                return None

            qname = _get_qualified_name(node.func)
            if qname and qname in self.summaries:
                summary = self.summaries[qname]
                if summary.returns_source:
                    return TaintInfo(
                        source_pattern=summary.source_pattern or "request.args.get",
                        source_line=summary.line or getattr(node, "lineno", 1),
                        propagation_path=[f"Source via {qname}()"],
                    )
                for idx in summary.returns_taint_from:
                    if idx < len(node.args):
                        arg_taint = self._expr_taint(node.args[idx], env)
                        if arg_taint:
                            return TaintInfo(
                                source_pattern=arg_taint.source_pattern,
                                source_line=arg_taint.source_line,
                                propagation_path=arg_taint.propagation_path
                                + [f"Line {getattr(node, 'lineno', 1)}: return from {qname}()"],
                            )
                if summary.has_sanitizer:
                    return None

            taint = self._expr_taint(getattr(node.func, "value", None), env)
            if taint:
                return taint
            for arg in node.args:
                taint = self._expr_taint(arg, env)
                if taint:
                    return taint
            for kw in node.keywords:
                taint = self._expr_taint(kw.value, env)
                if taint:
                    return taint
            return None

        for child in ast.iter_child_nodes(node):
            taint = self._expr_taint(child, env)
            if taint:
                return taint

        return None

    def _statement_findings(self, stmt: ast.stmt, env: Dict[str, TaintInfo]) -> List[dict]:
        findings: List[dict] = []

        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue

            sink = _match_sink(node)
            if sink:
                rule_id, message, relevant_args = sink
                for arg in relevant_args:
                    found = _find_first_taint(arg, env)
                    taint = self._expr_taint(arg, env)
                    if not taint:
                        continue
                    tainted_var = found[0] if found else ast.unparse(arg) if hasattr(ast, "unparse") else "expression"
                    taint_info = found[1] if found else taint
                    findings.append(
                        self._make_finding(
                            rule_id=rule_id,
                            message=message,
                            node=node,
                            tainted_variable=tainted_var,
                            taint_info=taint_info,
                        )
                    )

            qname = _get_qualified_name(node.func)
            if qname and qname in self.summaries:
                summary = self.summaries[qname]
                if summary.has_sanitizer:
                    continue
                for isink in summary.internal_sinks:
                    for idx in isink.param_indices:
                        if idx >= len(node.args):
                            continue
                        found = _find_first_taint(node.args[idx], env)
                        taint = self._expr_taint(node.args[idx], env)
                        if not taint:
                            continue
                        tainted_var = found[0] if found else ast.unparse(node.args[idx]) if hasattr(ast, "unparse") else "expression"
                        taint_info = found[1] if found else taint
                        findings.append(
                            self._make_finding(
                                rule_id=isink.rule_id,
                                message=f"{isink.message} Tainted data reaches sink inside {qname}().",
                                node=node,
                                tainted_variable=tainted_var,
                                taint_info=taint_info,
                                extra_metadata={"inter_procedural": True, "callee": qname},
                            )
                        )

        return findings

    @staticmethod
    def _make_finding(
        rule_id: str,
        message: str,
        node: ast.AST,
        tainted_variable: str,
        taint_info: TaintInfo,
        extra_metadata: Optional[Dict[str, object]] = None,
    ) -> dict:
        metadata = {
            "taint_source": taint_info.source_pattern,
            "taint_source_line": taint_info.source_line,
            "tainted_variable": tainted_variable,
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        return {
            "ruleId": rule_id,
            "message": message,
            "line": max(getattr(node, "lineno", 1) - 1, 0),
            "column": _node_column(node),
            "length": 0,
            "severity": "error",
            "confidence": "HIGH",
            "metadata": metadata,
            "engine": "taint",
        }


def analyze_python_taint(source: str, file_path: str = "<memory>") -> List[dict]:
    """Run lightweight Python taint analysis and return analyzer-style findings."""
    try:
        analyzer = _PythonTaintAnalyzer(source, file_path)
        return analyzer.analyze()
    except SyntaxError:
        return []
    except Exception:
        return []
