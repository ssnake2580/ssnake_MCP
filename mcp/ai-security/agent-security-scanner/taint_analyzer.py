"""
Taint Analysis Engine

Tracks dataflow from user-controlled sources to dangerous sinks.
Detects vulnerabilities only when tainted data reaches a sink.

Algorithm:
1. Find source patterns (user input) and mark matched variables as tainted
2. Track taint through assignments (y = x means y inherits x's taint)
3. Check if any tainted variable reaches a sink pattern
4. Report vulnerability if tainted data flows to sink
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from generic_ast import GenericNode, NodeKind
from pattern_matcher import (
    Pattern, TaintRule, Finding, PatternMatcher, 
    MatchResult, create_pattern
)


@dataclass
class TaintedVariable:
    """Represents a tainted variable and its source"""
    name: str
    source_pattern: str       # Which source pattern matched
    source_line: int          # Line where taint originated
    propagation_path: List[str] = field(default_factory=list)  # How taint flowed


@dataclass
class VariableAssignment:
    """Represents a variable assignment in the code"""
    target: str              # Variable being assigned to
    source_vars: Set[str]    # Variables used in the right-hand side
    line: int
    column: int
    node: GenericNode


@dataclass
class InternalSink:
    """A sink reached by a function parameter inside a function body."""
    sink_pattern: str
    param_indices: Set[int]  # Which param indices flow to this sink
    line: int
    rule_id: str


@dataclass
class FunctionSummary:
    """Summary of taint behavior for a single function."""
    name: str
    parameters: List[str]              # Param names in order (excluding self/cls)
    returns_taint_from: Set[int]       # Param indices whose taint flows to return
    returns_source: bool               # Body contains a taint source flowing to return
    source_pattern: Optional[str]
    internal_sinks: List[InternalSink]
    has_sanitizer: bool
    line: int
    end_line: int
    node: GenericNode


@dataclass
class CallGraph:
    """Call graph for functions within a single file."""
    functions: Dict[str, GenericNode]       # func name -> FUNCTION_DEF node
    summaries: Dict[str, FunctionSummary]   # func name -> summary
    calls: Dict[str, Set[str]]             # caller -> callees
    reverse: Dict[str, Set[str]]           # callee -> callers


class TaintAnalyzer:
    """
    Performs taint analysis on an AST using TaintRule definitions.
    
    Tracks how data flows from sources (user input) to sinks (dangerous functions).
    """
    
    def __init__(self):
        self.matcher = PatternMatcher()
        self.tainted: Dict[str, TaintedVariable] = {}
        self.assignments: List[VariableAssignment] = []
    
    def analyze(self, ast: GenericNode, rules: List[TaintRule]) -> List[Finding]:
        """
        Analyze AST for taint vulnerabilities using the provided rules.
        
        Returns list of findings where tainted data reaches a sink.
        """
        all_findings = []
        
        for rule in rules:
            findings = self._analyze_rule(ast, rule)
            all_findings.extend(findings)
        
        return all_findings
    
    def _analyze_rule(self, ast: GenericNode, rule: TaintRule) -> List[Finding]:
        """Analyze a single taint rule against the AST"""
        # Reset state for each rule
        self.tainted = {}
        self.assignments = []

        # Phase 0: Build call graph + generate inter-procedural summaries
        call_graph = self._build_call_graph(ast)
        summaries: Dict[str, FunctionSummary] = {}
        if call_graph.functions:
            summaries = self._generate_summaries(call_graph, rule)
        self._current_summaries = summaries

        # Step 1: Collect all variable assignments
        self._collect_assignments(ast)

        # Step 2: Find sources and mark initial tainted variables
        self._find_sources(ast, rule)

        # Step 3: Propagate taint through assignments (now includes inter-procedural)
        self._propagate_taint(rule)

        # Step 3.5: Check tainted args against callee internal sinks
        internal_findings = self._check_internal_sinks(ast, rule, summaries)

        # Step 4: Check sinks for tainted input
        findings = self._check_sinks(ast, rule)
        findings.extend(internal_findings)

        return findings
    
    def _collect_assignments(self, node: GenericNode):
        """Collect all variable assignments in the AST"""
        if node.kind == NodeKind.ASSIGNMENT:
            # Extract target and source variables
            target = self._get_assignment_target(node)
            source_vars = self._get_referenced_variables(node)
            
            if target:
                # Remove target from source vars (x = x + 1 shouldn't include x as source twice)
                source_vars.discard(target)
                
                self.assignments.append(VariableAssignment(
                    target=target,
                    source_vars=source_vars,
                    line=node.line,
                    column=node.column,
                    node=node
                ))
        
        # Recurse into children
        for child in node.children:
            self._collect_assignments(child)
    
    def _get_assignment_target(self, node: GenericNode) -> Optional[str]:
        """Extract the target variable name from an assignment"""
        # Look for identifier on the left side
        for child in node.children:
            if child.kind == NodeKind.IDENTIFIER:
                return child.text
            # Handle attribute access (obj.attr = ...)
            if child.kind == NodeKind.ATTRIBUTE:
                return child.text
        return None
    
    def _get_referenced_variables(self, node: GenericNode) -> Set[str]:
        """Get all variable names referenced in a node"""
        vars_found = set()
        
        def collect(n: GenericNode, skip_first: bool = False):
            # Skip the first identifier in assignments (that's the target)
            if n.kind == NodeKind.IDENTIFIER:
                if not skip_first:
                    vars_found.add(n.text)
            elif n.kind == NodeKind.CALL:
                # For function calls, check arguments
                for child in n.children:
                    collect(child, False)
            else:
                first_child = True
                for child in n.children:
                    collect(child, skip_first and first_child)
                    first_child = False
        
        collect(node, skip_first=True)
        return vars_found

    def _find_sources(self, ast: GenericNode, rule: TaintRule):
        """Find source patterns and mark matched variables as tainted"""
        for source_pattern in rule.sources:
            matches = self.matcher.find_all(source_pattern, ast)
            
            for match in matches:
                # Check if this source match is sanitized directly
                if match.node and self._is_sanitized(match.node, rule):
                    continue

                # Get the variable that receives the tainted value
                tainted_var = self._find_receiving_variable(match, ast)
                
                if tainted_var:
                    # Check if the assignment itself is sanitized (e.g. x = sanitize(source))
                    assignment = self._get_assignment_by_target(tainted_var)
                    if assignment and self._is_assignment_sanitized(assignment, rule):
                        continue
                        
                    self.tainted[tainted_var] = TaintedVariable(
                        name=tainted_var,
                        source_pattern=source_pattern.pattern_text,
                        source_line=match.line,
                        propagation_path=[f"Source: {source_pattern.pattern_text}"]
                    )
                
                # Check captured metavariables
                for meta_name, meta in match.metavariables.items():
                    if meta.text and meta.text not in self.tainted:
                        if meta.node and self._is_sanitized(meta.node, rule):
                            continue
                            
                        self.tainted[meta.text] = TaintedVariable(
                            name=meta.text,
                            source_pattern=source_pattern.pattern_text,
                            source_line=match.line,
                            propagation_path=[f"Captured: {meta_name}={meta.text}"]
                        )

    def _get_assignment_by_target(self, target: str) -> Optional[VariableAssignment]:
        for assignment in self.assignments:
            if assignment.target == target:
                return assignment
        return None

    def _is_sanitized(self, node: GenericNode, rule: TaintRule) -> bool:
        """Check if a node is covered by a sanitizer"""
        if not rule.sanitizers:
            return False
        for sanitizer in rule.sanitizers:
            if self.matcher.match(sanitizer, node):
                return True
        return False
    
    def _find_receiving_variable(self, match: MatchResult, ast: GenericNode) -> Optional[str]:
        """Find which variable receives the matched expression"""
        for assignment in self.assignments:
            if assignment.line == match.line:
                return assignment.target
        return None
    
    def _propagate_taint(self, rule: TaintRule):
        """Propagate taint through variable assignments (intra + inter-procedural)"""
        summaries = getattr(self, '_current_summaries', {})
        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for assignment in self.assignments:
                if assignment.target in self.tainted:
                    continue

                if self._is_assignment_sanitized(assignment, rule):
                    continue

                # Part A: Direct variable propagation (existing)
                for source_var in assignment.source_vars:
                    if source_var in self.tainted:
                        source_taint = self.tainted[source_var]
                        new_path = source_taint.propagation_path.copy()
                        new_path.append(f"Line {assignment.line}: {assignment.target} = ... {source_var} ...")

                        self.tainted[assignment.target] = TaintedVariable(
                            name=assignment.target,
                            source_pattern=source_taint.source_pattern,
                            source_line=source_taint.source_line,
                            propagation_path=new_path
                        )
                        changed = True
                        break

                if assignment.target in self.tainted:
                    continue

                # Part B: Inter-procedural return propagation
                if summaries:
                    call_nodes = assignment.node.find_all(NodeKind.CALL)
                    for call_node in call_nodes:
                        callee = self._resolve_callee_name(call_node)
                        if not callee or callee not in summaries:
                            continue
                        summary = summaries[callee]
                        if summary.has_sanitizer:
                            continue

                        # Check if callee returns a source
                        if summary.returns_source:
                            self.tainted[assignment.target] = TaintedVariable(
                                name=assignment.target,
                                source_pattern=summary.source_pattern or "function_source",
                                source_line=summary.line,
                                propagation_path=[f"Source via {callee}()"],
                            )
                            changed = True
                            break

                        # Check if any tainted arg flows to return
                        for idx, param_name in enumerate(summary.parameters):
                            if idx >= len(call_node.args):
                                continue
                            if idx not in summary.returns_taint_from:
                                continue
                            arg_node = call_node.args[idx]
                            arg_vars = self._get_referenced_variables(arg_node)
                            for av in arg_vars:
                                if av in self.tainted:
                                    source_taint = self.tainted[av]
                                    new_path = source_taint.propagation_path.copy()
                                    new_path.append(
                                        f"Line {assignment.line}: {assignment.target} = {callee}({av}) [inter-procedural]"
                                    )
                                    self.tainted[assignment.target] = TaintedVariable(
                                        name=assignment.target,
                                        source_pattern=source_taint.source_pattern,
                                        source_line=source_taint.source_line,
                                        propagation_path=new_path,
                                    )
                                    changed = True
                                    break
                            if assignment.target in self.tainted:
                                break
                        if assignment.target in self.tainted:
                            break
    
    def _is_assignment_sanitized(self, assignment: VariableAssignment, rule: TaintRule) -> bool:
        """Check if an assignment is sanitized"""
        if not rule.sanitizers:
            return False
        for sanitizer in rule.sanitizers:
            if self.matcher.find_all(sanitizer, assignment.node):
                return True
        return False
    
    def _check_sinks(self, ast: GenericNode, rule: TaintRule) -> List[Finding]:
        """Check if any tainted data reaches a sink"""
        findings = []
        
        for sink_pattern in rule.sinks:
            matches = self.matcher.find_all(sink_pattern, ast)
            
            for match in matches:
                # Find all tainted variables used in this sink match
                tainted_nodes = self._find_tainted_nodes_in_match(match)
                
                for var_name, var_node in tainted_nodes:
                    # Check if this usage is sanitized
                    if self._is_node_sanitized_in_context(var_node, match.node, rule):
                        continue
                        
                    taint_info = self.tainted[var_name]
                    path_str = " -> ".join(taint_info.propagation_path[-3:])
                    message = f"{rule.message}\n\nTaint flow: {path_str}\n\nTainted variable '{var_name}' flows to sink."
                    
                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        message=message,
                        severity=rule.severity,
                        line=match.line,
                        column=match.column,
                        text=match.node.text if match.node else "",
                        end_line=match.node.end_line if match.node else match.line,
                        end_column=match.node.end_column if match.node else match.column,
                        metavariables={k: v.text for k, v in match.metavariables.items()},
                        metadata={
                            **rule.metadata,
                            'taint_source': taint_info.source_pattern,
                            'taint_source_line': taint_info.source_line,
                            'tainted_variable': var_name
                        }
                    ))
        
        return findings

    def _find_tainted_nodes_in_match(self, match: MatchResult) -> List[Tuple[str, GenericNode]]:
        """Find tainted variables and their nodes within a match"""
        results = []
        
        # Check metavariables
        for meta in match.metavariables.values():
            if meta.text in self.tainted and meta.node:
                results.append((meta.text, meta.node))
                
        # If no metavariables, check all identifiers in the match node
        if not results and match.node:
            referenced = self._get_referenced_variables_with_nodes(match.node)
            for var_name, var_node in referenced:
                if var_name in self.tainted:
                    results.append((var_name, var_node))
                    
        return results

    def _get_referenced_variables_with_nodes(self, node: GenericNode) -> List[Tuple[str, GenericNode]]:
        """Get all variable names and nodes referenced in a node"""
        vars_found = []
        
        def collect(n: GenericNode):
            if n.kind == NodeKind.IDENTIFIER:
                vars_found.append((n.text, n))
            for child in n.children:
                collect(child)
        
        collect(node)
        return vars_found

    def _is_node_sanitized_in_context(self, target: GenericNode, context: GenericNode, rule: TaintRule) -> bool:
        """Check if target node is inside a sanitizer within context"""
        if not rule.sanitizers:
            return False
            
        # Find all sanitizer matches within context
        for sanitizer in rule.sanitizers:
            sanitizer_matches = self.matcher.find_all(sanitizer, context)
            for s_match in sanitizer_matches:
                if s_match.node and self._contains_range(s_match.node, target):
                    return True
        return False
        
    def _contains_range(self, outer: GenericNode, inner: GenericNode) -> bool:
        """Check if outer node lexically contains inner node"""
        # Simple line/column check
        if outer.line < inner.line or (outer.line == inner.line and outer.column <= inner.column):
            if outer.end_line > inner.end_line or (outer.end_line == inner.end_line and outer.end_column >= inner.end_column):
                return True
        return False
    
    # _find_tainted_in_match removed (replaced by _find_tainted_nodes_in_match)

    # ================================================================
    # Inter-procedural taint analysis (Phase 3)
    # ================================================================

    def _build_call_graph(self, ast: GenericNode) -> CallGraph:
        """Build a call graph for all functions in the file."""
        functions: Dict[str, GenericNode] = {}
        calls: Dict[str, Set[str]] = {}
        reverse: Dict[str, Set[str]] = {}

        # Collect all function definitions
        func_nodes = ast.find_all(NodeKind.FUNCTION_DEF)
        if len(func_nodes) > 500:
            return CallGraph(functions={}, summaries={}, calls={}, reverse={})

        for func_node in func_nodes:
            if func_node.name:
                functions[func_node.name] = func_node

        # Build call edges
        for func_name, func_node in functions.items():
            callees: Set[str] = set()
            call_nodes = func_node.find_all(NodeKind.CALL)
            for call_node in call_nodes:
                callee = self._resolve_callee_name(call_node)
                if callee and callee in functions and callee != func_name:
                    callees.add(callee)
                    if callee not in reverse:
                        reverse[callee] = set()
                    reverse[callee].add(func_name)
            calls[func_name] = callees

        return CallGraph(functions=functions, summaries={}, calls=calls, reverse=reverse)

    def _resolve_callee_name(self, call_node: GenericNode) -> Optional[str]:
        """Resolve the function name from a CALL node."""
        if call_node.name:
            # Handle dotted names: self.foo -> foo, obj.method -> method
            parts = call_node.name.split('.')
            return parts[-1]
        return None

    def _extract_param_names(self, func_node: GenericNode) -> List[str]:
        """Extract parameter names from a FUNCTION_DEF node, excluding self/cls."""
        names = []
        for param in func_node.params:
            if param.kind == NodeKind.IDENTIFIER:
                name = param.text
            else:
                ident = param.find_first(NodeKind.IDENTIFIER)
                name = ident.text if ident else None
            if name and name not in ('self', 'cls'):
                names.append(name)
        return names

    def _get_function_body(self, func_node: GenericNode) -> Optional[GenericNode]:
        """Find the block/body child of a function definition."""
        for child in func_node.children:
            if child.kind == NodeKind.BLOCK:
                return child
        return None

    # ----------------------------------------------------------------
    # Topological sort with SCC detection (Tarjan's algorithm)
    # ----------------------------------------------------------------

    def _topological_order(self, call_graph: CallGraph) -> List[List[str]]:
        """Return SCCs in reverse topological order (callees before callers)."""
        index_counter = [0]
        stack: List[str] = []
        on_stack: Set[str] = set()
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        result: List[List[str]] = []

        def strongconnect(v: str):
            indices[v] = index_counter[0]
            lowlinks[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            for w in call_graph.calls.get(v, set()):
                if w not in indices:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif w in on_stack:
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:
                scc: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    scc.append(w)
                    if w == v:
                        break
                result.append(scc)

        for v in call_graph.functions:
            if v not in indices:
                strongconnect(v)

        return result  # Already in reverse topological order from Tarjan's

    # ----------------------------------------------------------------
    # Function summary generation
    # ----------------------------------------------------------------

    def _generate_summaries(self, call_graph: CallGraph, rule: TaintRule) -> Dict[str, FunctionSummary]:
        """Generate function summaries in topological order."""
        summaries: Dict[str, FunctionSummary] = {}
        sccs = self._topological_order(call_graph)

        for scc in sccs:
            if len(scc) > 1:
                # Mutually recursive: conservative summary
                for func_name in scc:
                    func_node = call_graph.functions[func_name]
                    params = self._extract_param_names(func_node)
                    summaries[func_name] = FunctionSummary(
                        name=func_name,
                        parameters=params,
                        returns_taint_from=set(range(len(params))),
                        returns_source=False,
                        source_pattern=None,
                        internal_sinks=[],
                        has_sanitizer=False,
                        line=func_node.line,
                        end_line=func_node.end_line,
                        node=func_node,
                    )
            else:
                func_name = scc[0]
                func_node = call_graph.functions[func_name]
                summaries[func_name] = self._summarize_function(func_node, rule, summaries)

        call_graph.summaries = summaries
        return summaries

    def _summarize_function(self, func_node: GenericNode, rule: TaintRule,
                            existing_summaries: Dict[str, FunctionSummary]) -> FunctionSummary:
        """Generate a summary for a single non-recursive function."""
        params = self._extract_param_names(func_node)
        body = self._get_function_body(func_node)
        returns_taint_from: Set[int] = set()
        internal_sinks: List[InternalSink] = []
        returns_source = False
        source_pattern_str: Optional[str] = None
        has_sanitizer = False

        if not body:
            # No body found — try using the whole function node as body
            body = func_node

        # Check if body contains a sanitizer
        if rule.sanitizers:
            for sanitizer in rule.sanitizers:
                if self.matcher.find_all(sanitizer, body):
                    has_sanitizer = True
                    break

        # Check if body contains a taint source that flows to return
        for source_pattern in rule.sources:
            source_matches = self.matcher.find_all(source_pattern, body)
            if source_matches:
                # Check if any source flows to a return
                return_nodes = body.find_all(NodeKind.RETURN)
                if return_nodes:
                    returns_source = True
                    source_pattern_str = source_pattern.pattern_text

        # For each parameter, simulate taint and check what it reaches
        for i, param_name in enumerate(params):
            local_tainted: Dict[str, TaintedVariable] = {
                param_name: TaintedVariable(
                    name=param_name,
                    source_pattern=f"param:{param_name}",
                    source_line=func_node.line,
                    propagation_path=[f"Parameter: {param_name}"],
                )
            }

            # Collect assignments within this function body only
            local_assignments = self._collect_assignments_in_scope(body)

            # Propagate taint locally
            self._propagate_taint_local(local_tainted, local_assignments, rule, existing_summaries)

            # Check if taint reaches any RETURN node
            return_nodes = body.find_all(NodeKind.RETURN)
            for ret_node in return_nodes:
                ref_vars = self._get_referenced_variables(ret_node)
                for var in ref_vars:
                    if var in local_tainted:
                        returns_taint_from.add(i)
                        break
                if i in returns_taint_from:
                    break

            # Check if taint reaches any sink pattern
            for sink_pattern in rule.sinks:
                sink_matches = self.matcher.find_all(sink_pattern, body)
                for match in sink_matches:
                    if match.node:
                        ref_vars = self._get_referenced_variables(match.node)
                        for var in ref_vars:
                            if var in local_tainted:
                                internal_sinks.append(InternalSink(
                                    sink_pattern=sink_pattern.pattern_text,
                                    param_indices={i},
                                    line=match.line,
                                    rule_id=rule.id,
                                ))
                                break

        # Merge internal sinks with same line
        merged_sinks: Dict[int, InternalSink] = {}
        for sink in internal_sinks:
            if sink.line in merged_sinks:
                merged_sinks[sink.line].param_indices |= sink.param_indices
            else:
                merged_sinks[sink.line] = sink
        internal_sinks = list(merged_sinks.values())

        return FunctionSummary(
            name=func_node.name or "",
            parameters=params,
            returns_taint_from=returns_taint_from,
            returns_source=returns_source,
            source_pattern=source_pattern_str,
            internal_sinks=internal_sinks,
            has_sanitizer=has_sanitizer,
            line=func_node.line,
            end_line=func_node.end_line,
            node=func_node,
        )

    def _collect_assignments_in_scope(self, node: GenericNode) -> List[VariableAssignment]:
        """Collect assignments within a scope, stopping at nested FUNCTION_DEF boundaries."""
        assignments: List[VariableAssignment] = []

        def walk(n: GenericNode):
            if n.kind == NodeKind.FUNCTION_DEF and n is not node:
                return  # Don't descend into nested functions
            if n.kind == NodeKind.ASSIGNMENT:
                target = self._get_assignment_target(n)
                source_vars = self._get_referenced_variables(n)
                if target:
                    source_vars.discard(target)
                    assignments.append(VariableAssignment(
                        target=target,
                        source_vars=source_vars,
                        line=n.line,
                        column=n.column,
                        node=n,
                    ))
            for child in n.children:
                walk(child)

        walk(node)
        return assignments

    def _propagate_taint_local(self, tainted: Dict[str, TaintedVariable],
                               assignments: List[VariableAssignment],
                               rule: TaintRule,
                               existing_summaries: Dict[str, FunctionSummary]):
        """Propagate taint through assignments locally (within a function body)."""
        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for assignment in assignments:
                if assignment.target in tainted:
                    continue
                if self._is_assignment_sanitized(assignment, rule):
                    continue

                # Part A: Direct variable propagation
                for source_var in assignment.source_vars:
                    if source_var in tainted:
                        source_taint = tainted[source_var]
                        new_path = source_taint.propagation_path.copy()
                        new_path.append(f"Line {assignment.line}: {assignment.target} = ... {source_var} ...")
                        tainted[assignment.target] = TaintedVariable(
                            name=assignment.target,
                            source_pattern=source_taint.source_pattern,
                            source_line=source_taint.source_line,
                            propagation_path=new_path,
                        )
                        changed = True
                        break

                if assignment.target in tainted:
                    continue

                # Part B: Inter-procedural return propagation
                call_nodes = assignment.node.find_all(NodeKind.CALL)
                for call_node in call_nodes:
                    callee = self._resolve_callee_name(call_node)
                    if not callee or callee not in existing_summaries:
                        continue
                    summary = existing_summaries[callee]
                    if summary.has_sanitizer:
                        continue

                    # Check if callee returns a source
                    if summary.returns_source:
                        tainted[assignment.target] = TaintedVariable(
                            name=assignment.target,
                            source_pattern=summary.source_pattern or "function_source",
                            source_line=summary.line,
                            propagation_path=[f"Source via {callee}()"],
                        )
                        changed = True
                        break

                    # Check if any tainted arg flows to return
                    for idx, param_name in enumerate(summary.parameters):
                        if idx >= len(call_node.args):
                            continue
                        if idx not in summary.returns_taint_from:
                            continue
                        arg_node = call_node.args[idx]
                        arg_vars = self._get_referenced_variables(arg_node)
                        for av in arg_vars:
                            if av in tainted:
                                source_taint = tainted[av]
                                new_path = source_taint.propagation_path.copy()
                                new_path.append(f"Line {assignment.line}: {assignment.target} = {callee}({av}) [inter-procedural]")
                                tainted[assignment.target] = TaintedVariable(
                                    name=assignment.target,
                                    source_pattern=source_taint.source_pattern,
                                    source_line=source_taint.source_line,
                                    propagation_path=new_path,
                                )
                                changed = True
                                break
                        if assignment.target in tainted:
                            break
                    if assignment.target in tainted:
                        break

    # ----------------------------------------------------------------
    # Integration: check internal sinks at call sites
    # ----------------------------------------------------------------

    def _check_internal_sinks(self, ast: GenericNode, rule: TaintRule,
                              summaries: Dict[str, FunctionSummary]) -> List[Finding]:
        """Check tainted args at call sites against callee internal sinks."""
        findings: List[Finding] = []
        call_nodes = ast.find_all(NodeKind.CALL)

        for call_node in call_nodes:
            callee = self._resolve_callee_name(call_node)
            if not callee or callee not in summaries:
                continue
            summary = summaries[callee]
            if summary.has_sanitizer:
                continue

            for idx, param_name in enumerate(summary.parameters):
                if idx >= len(call_node.args):
                    continue
                arg_node = call_node.args[idx]
                arg_vars = self._get_referenced_variables(arg_node)
                for av in arg_vars:
                    if av not in self.tainted:
                        continue
                    taint_info = self.tainted[av]
                    for isink in summary.internal_sinks:
                        if idx in isink.param_indices:
                            path_str = " -> ".join(taint_info.propagation_path[-3:])
                            message = (
                                f"{rule.message}\n\n"
                                f"Taint flow: {path_str}\n\n"
                                f"Tainted variable '{av}' flows to sink inside {callee}() [inter-procedural]."
                            )
                            findings.append(Finding(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                message=message,
                                severity=rule.severity,
                                line=call_node.line,
                                column=call_node.column,
                                text=call_node.text,
                                end_line=call_node.end_line,
                                end_column=call_node.end_column,
                                metavariables={},
                                metadata={
                                    **rule.metadata,
                                    'taint_source': taint_info.source_pattern,
                                    'taint_source_line': taint_info.source_line,
                                    'tainted_variable': av,
                                    'inter_procedural': True,
                                    'callee': callee,
                                },
                            ))
                            break

        return findings


def analyze_taint(ast: GenericNode, rules: List[TaintRule]) -> List[Finding]:
    """Convenience function to run taint analysis"""
    analyzer = TaintAnalyzer()
    return analyzer.analyze(ast, rules)


if __name__ == '__main__':
    # Quick test
    print("TaintAnalyzer module loaded successfully")
    print("Use analyze_taint(ast, rules) to run taint analysis")
