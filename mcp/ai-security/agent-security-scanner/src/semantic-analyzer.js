/**
 * Semantic Code Analysis Layer
 *
 * Builds Code Property Graphs (CPG) combining:
 * - Control Flow Graph (CFG) - execution paths
 * - Data Flow Graph (DFG) - data dependencies
 * - AST - syntax structure
 *
 * Detects logic-level vulnerabilities that AST+regex miss:
 * - Missing authentication checks
 * - Race conditions
 * - TOCTOU (Time-of-Check-Time-of-Use)
 * - Unreachable code
 * - Logic contradictions
 * - Use-after-free patterns
 */

export class ControlFlowGraph {
  constructor(ast, language) {
    this.ast = ast;
    this.language = language;
    this.nodes = new Map(); // id -> CFGNode
    this.edges = []; // {from, to, type, condition}
    this.entryNode = null;
    this.exitNode = null;
    this.nodeCounter = 0;
  }

  /**
   * Build CFG from AST
   */
  build() {
    this.entryNode = this.createNode('entry', { type: 'entry' });
    this.exitNode = this.createNode('exit', { type: 'exit' });

    if (!this.ast) {
      this.addEdge(this.entryNode.id, this.exitNode.id, 'sequential');
      return this;
    }

    const bodyNode = this.processNode(this.ast, this.entryNode.id);
    if (bodyNode) {
      this.addEdge(bodyNode, this.exitNode.id, 'sequential');
    }

    return this;
  }

  /**
   * Process AST node and build CFG
   */
  processNode(node, prevNodeId) {
    if (!node || typeof node !== 'object') {
      return prevNodeId;
    }

    const nodeType = node.type || node.kind;

    switch (nodeType) {
      case 'program':
      case 'module':
      case 'source_file':
        return this.processSequence(node.body || node.children || [], prevNodeId);

      case 'function_definition':
      case 'function_declaration':
      case 'arrow_function':
      case 'method_definition':
        return this.processFunctionDeclaration(node, prevNodeId);

      case 'if_statement':
      case 'if':
        return this.processIfStatement(node, prevNodeId);

      case 'while_statement':
      case 'while':
      case 'for_statement':
      case 'for':
      case 'for_in_statement':
      case 'for_of_statement':
        return this.processLoop(node, prevNodeId);

      case 'try_statement':
      case 'try':
        return this.processTryStatement(node, prevNodeId);

      case 'return_statement':
      case 'return':
        return this.processReturn(node, prevNodeId);

      case 'throw_statement':
      case 'throw':
        return this.processThrow(node, prevNodeId);

      case 'break_statement':
      case 'break':
      case 'continue_statement':
      case 'continue':
        return this.processBreakContinue(node, prevNodeId);

      case 'switch_statement':
      case 'switch':
        return this.processSwitch(node, prevNodeId);

      case 'expression_statement':
      case 'call_expression':
      case 'assignment_expression':
      case 'variable_declaration':
        return this.processStatement(node, prevNodeId);

      case 'block_statement':
      case 'block':
        return this.processSequence(node.body || node.children || [], prevNodeId);

      default:
        // For unknown types, process children if available
        if (Array.isArray(node.children)) {
          return this.processSequence(node.children, prevNodeId);
        }
        return prevNodeId;
    }
  }

  /**
   * Process sequence of statements
   */
  processSequence(statements, prevNodeId) {
    let currentNode = prevNodeId;
    for (const stmt of statements) {
      if (currentNode === null) {
        // Previous statement was terminal (return/throw/break/continue)
        // Still process remaining statements to detect them as unreachable,
        // but don't pass prevNodeId (they won't be connected)
        this.processNode(stmt, null);
      } else {
        currentNode = this.processNode(stmt, currentNode);
      }
    }
    return currentNode;
  }

  /**
   * Process function declaration
   */
  processFunctionDeclaration(node, prevNodeId) {
    const funcNode = this.createNode('function', {
      type: 'function',
      name: this.extractFunctionName(node),
      params: this.extractParams(node),
      ast: node
    });

    this.addEdge(prevNodeId, funcNode.id, 'sequential');

    // Process function body
    const body = node.body;
    if (body) {
      const bodyEntry = this.createNode('block_entry', { type: 'block_entry' });
      const bodyExit = this.createNode('block_exit', { type: 'block_exit' });

      this.addEdge(funcNode.id, bodyEntry.id, 'function_enter');
      const lastNode = this.processNode(body, bodyEntry.id);
      this.addEdge(lastNode, bodyExit.id, 'sequential');
      this.addEdge(bodyExit.id, funcNode.id, 'function_exit');
    }

    return funcNode.id;
  }

  /**
   * Process if statement (creates branching)
   */
  processIfStatement(node, prevNodeId) {
    const condition = node.condition || node.test;
    const consequent = node.consequent || node.then_clause;
    const alternate = node.alternate || node.else_clause;

    const conditionNode = this.createNode('condition', {
      type: 'condition',
      condition: this.extractExpression(condition),
      ast: condition
    });

    this.addEdge(prevNodeId, conditionNode.id, 'sequential');

    // True branch
    const trueNode = this.processNode(consequent, conditionNode.id);
    this.addEdge(conditionNode.id, trueNode, 'true_branch', this.extractExpression(condition));

    // False branch (else or merge point)
    let falseNode;
    if (alternate) {
      falseNode = this.processNode(alternate, conditionNode.id);
      this.addEdge(conditionNode.id, falseNode, 'false_branch', `!(${this.extractExpression(condition)})`);
    } else {
      falseNode = conditionNode.id;
    }

    // Merge point
    const mergeNode = this.createNode('merge', { type: 'merge' });
    this.addEdge(trueNode, mergeNode.id, 'merge');
    this.addEdge(falseNode, mergeNode.id, 'merge');

    return mergeNode.id;
  }

  /**
   * Process loop statement
   */
  processLoop(node, prevNodeId) {
    const loopHeader = this.createNode('loop_header', {
      type: 'loop_header',
      loopType: node.type,
      condition: this.extractExpression(node.condition || node.test),
      ast: node
    });

    this.addEdge(prevNodeId, loopHeader.id, 'sequential');

    const loopBody = this.processNode(node.body, loopHeader.id);

    // Back edge (loop iteration)
    this.addEdge(loopBody, loopHeader.id, 'back_edge');

    // Exit edge (loop exit)
    const exitNode = this.createNode('loop_exit', { type: 'loop_exit' });
    this.addEdge(loopHeader.id, exitNode.id, 'loop_exit');

    return exitNode.id;
  }

  /**
   * Process try-catch-finally
   */
  processTryStatement(node, prevNodeId) {
    const tryBlock = node.body || node.try_clause;
    const catchClause = node.handler || node.catch_clause;
    const finallyBlock = node.finalizer || node.finally_clause;

    const tryNode = this.createNode('try', { type: 'try', ast: node });
    this.addEdge(prevNodeId, tryNode.id, 'sequential');

    const tryBodyNode = this.processNode(tryBlock, tryNode.id);

    let mergeNode = this.createNode('merge', { type: 'merge' });

    // Normal path
    this.addEdge(tryBodyNode, mergeNode.id, 'normal');

    // Exception path
    if (catchClause) {
      const catchNode = this.processNode(catchClause.body, tryNode.id);
      this.addEdge(tryNode.id, catchNode, 'exception');
      this.addEdge(catchNode, mergeNode.id, 'merge');
    }

    // Finally always executes
    if (finallyBlock) {
      const finallyNode = this.processNode(finallyBlock, mergeNode.id);
      return finallyNode;
    }

    return mergeNode.id;
  }

  /**
   * Process return statement
   */
  processReturn(node, prevNodeId) {
    const returnNode = this.createNode('return', {
      type: 'return',
      value: this.extractExpression(node.argument || node.value),
      ast: node
    });

    this.addEdge(prevNodeId, returnNode.id, 'sequential');
    this.addEdge(returnNode.id, this.exitNode.id, 'return');

    // Return null to indicate no subsequent code should be connected
    return null;
  }

  /**
   * Process throw statement
   */
  processThrow(node, prevNodeId) {
    const throwNode = this.createNode('throw', {
      type: 'throw',
      value: this.extractExpression(node.argument || node.value),
      ast: node
    });

    this.addEdge(prevNodeId, throwNode.id, 'sequential');
    this.addEdge(throwNode.id, this.exitNode.id, 'exception');

    // Return null to indicate no subsequent code should be connected
    return null;
  }

  /**
   * Process break/continue
   */
  processBreakContinue(node, prevNodeId) {
    const jumpNode = this.createNode(node.type, {
      type: node.type,
      label: node.label?.name,
      ast: node
    });

    this.addEdge(prevNodeId, jumpNode.id, 'sequential');
    // Note: Need to find target loop header/exit in post-processing

    return jumpNode.id;
  }

  /**
   * Process switch statement
   */
  processSwitch(node, prevNodeId) {
    const switchNode = this.createNode('switch', {
      type: 'switch',
      discriminant: this.extractExpression(node.discriminant || node.value),
      ast: node
    });

    this.addEdge(prevNodeId, switchNode.id, 'sequential');

    const cases = node.cases || node.children?.filter(c => c.type === 'switch_case') || [];
    const mergeNode = this.createNode('merge', { type: 'merge' });

    for (const caseNode of cases) {
      const caseValue = caseNode.test || caseNode.value;
      const caseBodyNode = this.processSequence(caseNode.consequent || caseNode.children || [], switchNode.id);

      this.addEdge(switchNode.id, caseBodyNode, 'case', this.extractExpression(caseValue));
      this.addEdge(caseBodyNode, mergeNode.id, 'merge');
    }

    return mergeNode.id;
  }

  /**
   * Process regular statement
   */
  processStatement(node, prevNodeId) {
    const stmtNode = this.createNode('statement', {
      type: 'statement',
      statementType: node.type,
      expression: this.extractExpression(node),
      ast: node
    });

    this.addEdge(prevNodeId, stmtNode.id, 'sequential');
    return stmtNode.id;
  }

  /**
   * Create CFG node
   */
  createNode(type, data = {}) {
    const id = `node_${this.nodeCounter++}`;
    const node = { id, type, ...data };
    this.nodes.set(id, node);
    return node;
  }

  /**
   * Add CFG edge
   */
  addEdge(fromId, toId, type = 'sequential', condition = null) {
    if (!fromId || !toId) return;
    this.edges.push({ from: fromId, to: toId, type, condition });
  }

  /**
   * Extract function name from node
   */
  extractFunctionName(node) {
    if (node.id?.name) return node.id.name;
    if (node.name?.text) return node.name.text;
    if (node.declarator?.name) return node.declarator.name;
    return '<anonymous>';
  }

  /**
   * Extract function parameters
   */
  extractParams(node) {
    const params = node.parameters || node.params || [];
    return params.map(p => {
      if (typeof p === 'string') return p;
      if (p.name?.text) return p.name.text;
      if (p.text) return p.text;
      return '<param>';
    });
  }

  /**
   * Extract expression as string (simplified)
   */
  extractExpression(node) {
    if (!node) return '';
    if (typeof node === 'string') return node;
    if (node.text) return node.text;
    if (node.name) return node.name;
    if (node.type === 'identifier' && node.value) return node.value;
    return `<${node.type || 'expr'}>`;
  }

  /**
   * Get all paths from entry to exit
   */
  getAllPaths(maxDepth = 100) {
    const paths = [];
    const visited = new Set();

    const dfs = (nodeId, path, depth) => {
      if (depth > maxDepth) return; // Prevent infinite loops
      if (nodeId === this.exitNode.id) {
        paths.push([...path]);
        return;
      }
      if (visited.has(nodeId)) return;

      visited.add(nodeId);
      path.push(nodeId);

      const outgoingEdges = this.edges.filter(e => e.from === nodeId);
      for (const edge of outgoingEdges) {
        dfs(edge.to, path, depth + 1);
      }

      path.pop();
      visited.delete(nodeId);
    };

    dfs(this.entryNode.id, [], 0);
    return paths;
  }

  /**
   * Find all reachable nodes from a given node
   */
  getReachableNodes(startNodeId) {
    const reachable = new Set();
    const queue = [startNodeId];

    while (queue.length > 0) {
      const nodeId = queue.shift();
      if (reachable.has(nodeId)) continue;

      reachable.add(nodeId);
      const outgoing = this.edges.filter(e => e.from === nodeId);
      for (const edge of outgoing) {
        queue.push(edge.to);
      }
    }

    return reachable;
  }

  /**
   * Find unreachable nodes (dead code)
   */
  getUnreachableNodes() {
    const reachable = this.getReachableNodes(this.entryNode.id);
    const unreachable = [];

    for (const [nodeId, node] of this.nodes) {
      if (!reachable.has(nodeId) && nodeId !== this.exitNode.id) {
        unreachable.push({ nodeId, node });
      }
    }

    return unreachable;
  }

  /**
   * Export to DOT format for visualization
   */
  toDot() {
    let dot = 'digraph CFG {\n';
    dot += '  rankdir=TB;\n';
    dot += '  node [shape=box];\n\n';

    // Nodes
    for (const [id, node] of this.nodes) {
      const label = this.getNodeLabel(node);
      const shape = this.getNodeShape(node.type);
      dot += `  ${id} [label="${label}", shape=${shape}];\n`;
    }

    dot += '\n';

    // Edges
    for (const edge of this.edges) {
      const style = this.getEdgeStyle(edge.type);
      const label = edge.condition ? `[label="${edge.condition}"]` : '';
      dot += `  ${edge.from} -> ${edge.to} ${label} ${style};\n`;
    }

    dot += '}\n';
    return dot;
  }

  getNodeLabel(node) {
    switch (node.type) {
      case 'entry': return 'ENTRY';
      case 'exit': return 'EXIT';
      case 'function': return `func ${node.name}`;
      case 'condition': return `if (${node.condition})`;
      case 'loop_header': return `loop (${node.condition})`;
      case 'statement': return node.expression || 'stmt';
      case 'return': return `return ${node.value}`;
      default: return node.type;
    }
  }

  getNodeShape(type) {
    switch (type) {
      case 'entry':
      case 'exit':
        return 'ellipse';
      case 'condition':
        return 'diamond';
      case 'merge':
        return 'circle';
      default:
        return 'box';
    }
  }

  getEdgeStyle(type) {
    switch (type) {
      case 'true_branch':
        return '[color=green]';
      case 'false_branch':
        return '[color=red]';
      case 'exception':
        return '[style=dashed, color=red]';
      case 'back_edge':
        return '[style=dashed, color=blue]';
      default:
        return '';
    }
  }
}

/**
 * Data Flow Graph - tracks data dependencies
 */
export class DataFlowGraph {
  constructor(cfg, ast) {
    this.cfg = cfg;
    this.ast = ast;
    this.definitions = new Map(); // variable -> Set of definition nodes
    this.uses = new Map(); // variable -> Set of use nodes
    this.reachingDefs = new Map(); // nodeId -> Map(variable -> Set of def nodes)
    this.liveVars = new Map(); // nodeId -> Set of live variables
  }

  /**
   * Build DFG using reaching definitions analysis
   */
  build() {
    this.analyzeDefinitionsAndUses();
    this.computeReachingDefinitions();
    this.computeLiveVariables();
    return this;
  }

  /**
   * Extract definitions and uses from CFG nodes
   */
  analyzeDefinitionsAndUses() {
    for (const [nodeId, node] of this.cfg.nodes) {
      if (!node.ast) continue;

      const defs = this.extractDefinitions(node.ast);
      const uses = this.extractUses(node.ast);

      for (const varName of defs) {
        if (!this.definitions.has(varName)) {
          this.definitions.set(varName, new Set());
        }
        this.definitions.get(varName).add(nodeId);
      }

      for (const varName of uses) {
        if (!this.uses.has(varName)) {
          this.uses.set(varName, new Set());
        }
        this.uses.get(varName).add(nodeId);
      }
    }
  }

  /**
   * Extract variable definitions from AST node
   */
  extractDefinitions(node) {
    const defs = new Set();
    if (!node || typeof node !== 'object') return defs;

    const type = node.type || node.kind;

    switch (type) {
      case 'variable_declaration':
      case 'lexical_declaration':
        if (node.declarations) {
          for (const decl of node.declarations) {
            const name = this.extractVariableName(decl.id || decl.name);
            if (name) defs.add(name);
          }
        }
        break;

      case 'assignment_expression':
      case 'assignment':
        const leftName = this.extractVariableName(node.left || node.lhs);
        if (leftName) defs.add(leftName);
        break;

      case 'update_expression':
        const argName = this.extractVariableName(node.argument);
        if (argName) defs.add(argName);
        break;

      case 'for_statement':
      case 'for':
        if (node.init) {
          const initDefs = this.extractDefinitions(node.init);
          initDefs.forEach(d => defs.add(d));
        }
        break;
    }

    return defs;
  }

  /**
   * Extract variable uses from AST node
   */
  extractUses(node) {
    const uses = new Set();
    if (!node || typeof node !== 'object') return uses;

    // Simple heuristic: any identifier reference is a use
    // (except in definition contexts which are handled separately)
    this.walkNode(node, (n) => {
      if ((n.type === 'identifier' || n.kind === 'identifier') && n.name) {
        uses.add(n.name);
      }
    });

    return uses;
  }

  /**
   * Walk AST node recursively
   */
  walkNode(node, callback) {
    if (!node || typeof node !== 'object') return;

    callback(node);

    if (Array.isArray(node.children)) {
      node.children.forEach(child => this.walkNode(child, callback));
    }

    // Common AST properties
    const props = ['body', 'consequent', 'alternate', 'test', 'argument',
                   'left', 'right', 'object', 'property', 'callee', 'arguments', 'expression'];

    for (const prop of props) {
      if (node[prop]) {
        if (Array.isArray(node[prop])) {
          node[prop].forEach(child => this.walkNode(child, callback));
        } else {
          this.walkNode(node[prop], callback);
        }
      }
    }
  }

  /**
   * Extract variable name from node
   */
  extractVariableName(node) {
    if (!node) return null;
    if (typeof node === 'string') return node;
    if (node.name) return node.name;
    if (node.text) return node.text;
    return null;
  }

  /**
   * Compute reaching definitions (which definitions reach each node)
   */
  computeReachingDefinitions() {
    // Iterative worklist algorithm
    const worklist = Array.from(this.cfg.nodes.keys());

    // Initialize
    for (const nodeId of this.cfg.nodes.keys()) {
      this.reachingDefs.set(nodeId, new Map());
    }

    while (worklist.length > 0) {
      const nodeId = worklist.shift();
      const node = this.cfg.nodes.get(nodeId);

      // IN[node] = Union of OUT[pred] for all predecessors
      const inDefs = new Map();
      const predecessors = this.cfg.edges.filter(e => e.to === nodeId);

      for (const pred of predecessors) {
        const predOut = this.reachingDefs.get(pred.from);
        if (predOut) {
          for (const [varName, defNodes] of predOut) {
            if (!inDefs.has(varName)) {
              inDefs.set(varName, new Set());
            }
            defNodes.forEach(d => inDefs.get(varName).add(d));
          }
        }
      }

      // GEN[node] = definitions generated by this node
      // KILL[node] = definitions killed by this node
      const gen = new Map(inDefs);
      const defs = this.extractDefinitions(node.ast || {});

      for (const varName of defs) {
        gen.set(varName, new Set([nodeId]));
      }

      // OUT[node] = GEN[node] ∪ (IN[node] - KILL[node])
      const oldOut = this.reachingDefs.get(nodeId);
      this.reachingDefs.set(nodeId, gen);

      // Check if changed
      if (!this.mapsEqual(oldOut, gen)) {
        // Add successors to worklist
        const successors = this.cfg.edges.filter(e => e.from === nodeId);
        for (const succ of successors) {
          if (!worklist.includes(succ.to)) {
            worklist.push(succ.to);
          }
        }
      }
    }
  }

  /**
   * Compute live variables (which variables are live at each node)
   */
  computeLiveVariables() {
    // Backward analysis
    const worklist = Array.from(this.cfg.nodes.keys());

    for (const nodeId of this.cfg.nodes.keys()) {
      this.liveVars.set(nodeId, new Set());
    }

    while (worklist.length > 0) {
      const nodeId = worklist.shift();
      const node = this.cfg.nodes.get(nodeId);

      // OUT[node] = Union of IN[succ] for all successors
      const outLive = new Set();
      const successors = this.cfg.edges.filter(e => e.from === nodeId);

      for (const succ of successors) {
        const succIn = this.liveVars.get(succ.to);
        if (succIn) {
          succIn.forEach(v => outLive.add(v));
        }
      }

      // IN[node] = USE[node] ∪ (OUT[node] - DEF[node])
      const uses = this.extractUses(node.ast || {});
      const defs = this.extractDefinitions(node.ast || {});

      const inLive = new Set(uses);
      for (const v of outLive) {
        if (!defs.has(v)) {
          inLive.add(v);
        }
      }

      const oldIn = this.liveVars.get(nodeId);
      this.liveVars.set(nodeId, inLive);

      // Check if changed
      if (!this.setsEqual(oldIn, inLive)) {
        const predecessors = this.cfg.edges.filter(e => e.to === nodeId);
        for (const pred of predecessors) {
          if (!worklist.includes(pred.from)) {
            worklist.push(pred.from);
          }
        }
      }
    }
  }

  /**
   * Helper: compare two Maps of Sets
   */
  mapsEqual(map1, map2) {
    if (!map1 || !map2) return map1 === map2;
    if (map1.size !== map2.size) return false;

    for (const [key, set1] of map1) {
      const set2 = map2.get(key);
      if (!this.setsEqual(set1, set2)) return false;
    }
    return true;
  }

  /**
   * Helper: compare two Sets
   */
  setsEqual(set1, set2) {
    if (!set1 || !set2) return set1 === set2;
    if (set1.size !== set2.size) return false;
    for (const item of set1) {
      if (!set2.has(item)) return false;
    }
    return true;
  }

  /**
   * Find use-def chains (which definitions reach a use)
   */
  getUseDefChain(nodeId, varName) {
    const reachingDefs = this.reachingDefs.get(nodeId);
    if (!reachingDefs) return [];
    return Array.from(reachingDefs.get(varName) || []);
  }

  /**
   * Find def-use chains (which uses are reached by a definition)
   */
  getDefUseChain(defNodeId, varName) {
    const uses = [];
    for (const [nodeId, reachingDefs] of this.reachingDefs) {
      const defs = reachingDefs.get(varName);
      if (defs && defs.has(defNodeId)) {
        const nodeUses = this.extractUses(this.cfg.nodes.get(nodeId).ast || {});
        if (nodeUses.has(varName)) {
          uses.push(nodeId);
        }
      }
    }
    return uses;
  }
}

/**
 * Code Property Graph - combines CFG and DFG
 */
export class CodePropertyGraph {
  constructor(ast, language) {
    this.ast = ast;
    this.language = language;
    this.cfg = null;
    this.dfg = null;
  }

  build() {
    this.cfg = new ControlFlowGraph(this.ast, this.language).build();
    this.dfg = new DataFlowGraph(this.cfg, this.ast).build();
    return this;
  }

  /**
   * Get CFG
   */
  getControlFlowGraph() {
    return this.cfg;
  }

  /**
   * Get DFG
   */
  getDataFlowGraph() {
    return this.dfg;
  }

  /**
   * Export combined graph to DOT
   */
  toDot() {
    return this.cfg.toDot();
  }
}

/**
 * Semantic Pattern Matcher - detects security patterns in CPG
 */
export class SemanticPatternMatcher {
  constructor(cpg) {
    this.cpg = cpg;
    this.findings = [];
  }

  /**
   * Run all semantic pattern checks
   */
  analyze() {
    this.findings = [];

    this.detectUnreachableCode();
    this.detectMissingAuthChecks();
    this.detectRaceConditions();
    this.detectTOCTOU();
    this.detectLogicContradictions();
    this.detectUseAfterFree();
    this.detectNullDereference();
    this.detectDeadStores();

    return this.findings;
  }

  /**
   * Detect unreachable code (dead code)
   */
  detectUnreachableCode() {
    const unreachable = this.cpg.cfg.getUnreachableNodes();

    for (const { nodeId, node } of unreachable) {
      if (node.type === 'statement' || node.type === 'function') {
        this.findings.push({
          ruleId: 'semantic.unreachable-code',
          message: 'Unreachable code detected - this code will never execute',
          severity: 'warning',
          nodeId,
          node,
          category: 'dead-code',
          confidence: 'high'
        });
      }
    }
  }

  /**
   * Detect missing authentication checks before sensitive operations
   */
  detectMissingAuthChecks() {
    const sensitiveOps = ['db.delete', 'db.update', 'executeCommand', 'readFile', 'writeFile'];

    for (const [nodeId, node] of this.cpg.cfg.nodes) {
      if (node.type !== 'statement') continue;

      const expr = node.expression || '';
      const hasSensitiveOp = sensitiveOps.some(op => expr.includes(op));

      if (hasSensitiveOp) {
        // Check if there's an auth check in the path from entry to this node
        const hasAuthCheck = this.hasAuthCheckInPath(this.cpg.cfg.entryNode.id, nodeId);

        if (!hasAuthCheck) {
          this.findings.push({
            ruleId: 'semantic.missing-auth-check',
            message: `Sensitive operation '${expr}' executed without authentication check`,
            severity: 'error',
            nodeId,
            node,
            category: 'auth-bypass',
            confidence: 'medium'
          });
        }
      }
    }
  }

  /**
   * Check if there's an auth check in path from start to end node
   */
  hasAuthCheckInPath(startNodeId, endNodeId) {
    const authPatterns = ['isAuthenticated', 'checkAuth', 'requireAuth', 'req.user', 'user.id'];
    const visited = new Set();

    const dfs = (nodeId) => {
      if (nodeId === endNodeId) return false;
      if (visited.has(nodeId)) return false;
      visited.add(nodeId);

      const node = this.cpg.cfg.nodes.get(nodeId);
      if (node && node.expression) {
        const hasAuth = authPatterns.some(pattern => node.expression.includes(pattern));
        if (hasAuth) return true;
      }

      const edges = this.cpg.cfg.edges.filter(e => e.from === nodeId);
      for (const edge of edges) {
        if (dfs(edge.to)) return true;
      }

      return false;
    };

    return dfs(startNodeId);
  }

  /**
   * Detect potential race conditions (concurrent access without locks)
   */
  detectRaceConditions() {
    // Look for shared variable access without synchronization
    const sharedVarAccess = new Map(); // varName -> [nodeIds]

    for (const [nodeId, node] of this.cpg.cfg.nodes) {
      const defs = this.cpg.dfg.extractDefinitions(node.ast || {});
      const uses = this.cpg.dfg.extractUses(node.ast || {});

      for (const varName of [...defs, ...uses]) {
        if (!sharedVarAccess.has(varName)) {
          sharedVarAccess.set(varName, []);
        }
        sharedVarAccess.get(varName).push(nodeId);
      }
    }

    // Check for variables accessed in multiple places without locks
    for (const [varName, accessNodes] of sharedVarAccess) {
      if (accessNodes.length < 2) continue;

      const hasLock = this.hasLockProtection(accessNodes);

      if (!hasLock && this.isLikelySharedState(varName)) {
        this.findings.push({
          ruleId: 'semantic.race-condition',
          message: `Potential race condition: variable '${varName}' accessed concurrently without synchronization`,
          severity: 'warning',
          category: 'concurrency',
          confidence: 'low',
          affectedNodes: accessNodes
        });
      }
    }
  }

  /**
   * Check if accesses are protected by locks
   */
  hasLockProtection(nodeIds) {
    const lockPatterns = ['lock(', 'mutex.', 'synchronized', 'Lock()', 'acquire()'];

    for (const nodeId of nodeIds) {
      const node = this.cpg.cfg.nodes.get(nodeId);
      if (node && node.expression) {
        const hasLock = lockPatterns.some(pattern => node.expression.includes(pattern));
        if (hasLock) return true;
      }
    }
    return false;
  }

  /**
   * Heuristic: is this likely a shared state variable?
   */
  isLikelySharedState(varName) {
    const sharedPatterns = ['cache', 'state', 'global', 'shared', 'counter', 'pool'];
    return sharedPatterns.some(pattern => varName.toLowerCase().includes(pattern));
  }

  /**
   * Detect TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
   */
  detectTOCTOU() {
    // Look for check-then-use patterns with file operations
    const checkPatterns = ['exists', 'isFile', 'access', 'stat'];
    const usePatterns = ['readFile', 'writeFile', 'unlink', 'open'];

    for (const path of this.cpg.cfg.getAllPaths(50)) {
      let checkNode = null;
      let checkVar = null;

      for (let i = 0; i < path.length - 1; i++) {
        const nodeId = path[i];
        const node = this.cpg.cfg.nodes.get(nodeId);
        const expr = node.expression || '';

        // Found a check
        const isCheck = checkPatterns.some(p => expr.includes(p));
        if (isCheck) {
          checkNode = node;
          checkVar = this.extractFilePathVar(expr);
        }

        // Found a use after check
        const isUse = usePatterns.some(p => expr.includes(p));
        if (isUse && checkNode && checkVar) {
          const useVar = this.extractFilePathVar(expr);

          if (useVar === checkVar) {
            this.findings.push({
              ruleId: 'semantic.toctou',
              message: `TOCTOU vulnerability: file check at node ${checkNode.id} followed by use at node ${nodeId} - file state may change between check and use`,
              severity: 'error',
              category: 'race-condition',
              confidence: 'medium',
              checkNode: checkNode.id,
              useNode: nodeId
            });
          }
        }
      }
    }
  }

  /**
   * Extract file path variable from expression
   */
  extractFilePathVar(expr) {
    const match = expr.match(/['"]([^'"]+)['"]/);
    return match ? match[1] : null;
  }

  /**
   * Detect logic contradictions (impossible conditions)
   */
  detectLogicContradictions() {
    for (const path of this.cpg.cfg.getAllPaths(50)) {
      const conditions = new Set();

      for (const nodeId of path) {
        const node = this.cpg.cfg.nodes.get(nodeId);

        if (node.type === 'condition') {
          const cond = node.condition;

          // Check if we already have the negation of this condition
          const negation = this.getNegation(cond);
          if (conditions.has(negation)) {
            this.findings.push({
              ruleId: 'semantic.logic-contradiction',
              message: `Logic contradiction detected: condition '${cond}' conflicts with earlier condition '${negation}'`,
              severity: 'warning',
              nodeId,
              category: 'logic-error',
              confidence: 'high'
            });
          }

          conditions.add(cond);
        }
      }
    }
  }

  /**
   * Get negation of condition
   */
  getNegation(cond) {
    if (cond.startsWith('!(')) {
      return cond.slice(2, -1);
    }
    return `!(${cond})`;
  }

  /**
   * Detect use-after-free patterns (C/C++)
   */
  detectUseAfterFree() {
    if (!['c', 'cpp'].includes(this.cpg.language)) return;

    for (const [varName, defNodes] of this.cpg.dfg.definitions) {
      for (const defNodeId of defNodes) {
        const defNode = this.cpg.cfg.nodes.get(defNodeId);
        const expr = defNode.expression || '';

        if (expr.includes('free(') || expr.includes('delete ')) {
          // Check if variable is used after free
          const useNodes = this.cpg.dfg.getDefUseChain(defNodeId, varName);

          if (useNodes.length > 0) {
            this.findings.push({
              ruleId: 'semantic.use-after-free',
              message: `Use-after-free detected: variable '${varName}' used after being freed`,
              severity: 'error',
              category: 'memory-safety',
              confidence: 'high',
              freeNode: defNodeId,
              useNodes
            });
          }
        }
      }
    }
  }

  /**
   * Detect null pointer dereference
   */
  detectNullDereference() {
    for (const [nodeId, node] of this.cpg.cfg.nodes) {
      const expr = node.expression || '';

      // Look for null checks followed by dereference
      if (expr.includes('null') || expr.includes('nil') || expr.includes('None')) {
        const edges = this.cpg.cfg.edges.filter(e => e.from === nodeId && e.type === 'true_branch');

        for (const edge of edges) {
          const targetNode = this.cpg.cfg.nodes.get(edge.to);
          if (targetNode && (targetNode.expression || '').includes('.')) {
            this.findings.push({
              ruleId: 'semantic.null-dereference',
              message: 'Potential null pointer dereference after null check',
              severity: 'warning',
              category: 'null-safety',
              confidence: 'low',
              checkNode: nodeId,
              derefNode: edge.to
            });
          }
        }
      }
    }
  }

  /**
   * Detect dead stores (assignments to variables never used)
   */
  detectDeadStores() {
    for (const [varName, defNodes] of this.cpg.dfg.definitions) {
      for (const defNodeId of defNodes) {
        const useNodes = this.cpg.dfg.getDefUseChain(defNodeId, varName);

        if (useNodes.length === 0) {
          const defNode = this.cpg.cfg.nodes.get(defNodeId);

          this.findings.push({
            ruleId: 'semantic.dead-store',
            message: `Dead store: assignment to variable '${varName}' is never used`,
            severity: 'info',
            category: 'optimization',
            confidence: 'high',
            nodeId: defNodeId
          });
        }
      }
    }
  }
}

/**
 * Main Semantic Analyzer
 */
export class SemanticAnalyzer {
  constructor(ast, language, filePath) {
    this.ast = ast;
    this.language = language;
    this.filePath = filePath;
    this.cpg = null;
    this.findings = [];
  }

  /**
   * Run semantic analysis
   */
  analyze() {
    try {
      // Build CPG
      this.cpg = new CodePropertyGraph(this.ast, this.language).build();

      // Run pattern matching
      const matcher = new SemanticPatternMatcher(this.cpg);
      this.findings = matcher.analyze();

      return this.findings;
    } catch (error) {
      console.error(`Semantic analysis error: ${error.message}`);
      return [];
    }
  }

  /**
   * Get Code Property Graph
   */
  getCPG() {
    return this.cpg;
  }

  /**
   * Export CPG to DOT format for visualization
   */
  exportDot() {
    return this.cpg ? this.cpg.toDot() : '';
  }
}
