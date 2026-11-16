// src/lib/normalize-finding.js — Normalize findings from 6 different tool shapes into one internal format.

const SEVERITY_MAP = {
  'error': { severity: 'HIGH', severity_rank: 3 },
  'ERROR': { severity: 'HIGH', severity_rank: 3 },
  'warning': { severity: 'MEDIUM', severity_rank: 2 },
  'WARNING': { severity: 'MEDIUM', severity_rank: 2 },
  'info': { severity: 'INFO', severity_rank: 0 },
  'INFO': { severity: 'INFO', severity_rank: 0 },
  'CRITICAL': { severity: 'CRITICAL', severity_rank: 4 },
  'critical': { severity: 'CRITICAL', severity_rank: 4 },
  'LOW': { severity: 'LOW', severity_rank: 1 },
  'low': { severity: 'LOW', severity_rank: 1 },
  'HIGH': { severity: 'HIGH', severity_rank: 3 },
  'high': { severity: 'HIGH', severity_rank: 3 },
  'MEDIUM': { severity: 'MEDIUM', severity_rank: 2 },
  'medium': { severity: 'MEDIUM', severity_rank: 2 },
};

const DEFAULT_SEVERITY = { severity: 'MEDIUM', severity_rank: 2 };

// Map ruleId segments to categories for tools that don't emit category directly.
// Keyed by the second dotted segment of ruleId (e.g. "injection" from "python.injection.sql-injection").
const RULE_CATEGORY_MAP = {
  'injection': 'injection',
  'crypto': 'crypto',
  'auth': 'auth',
  'xss': 'xss',
  'ssrf': 'ssrf',
  'path': 'path-traversal',
  'deserialization': 'deserialization',
  'info': 'info-exposure',
  'permissions': 'permissions',
  'logging': 'info-exposure',
  'secrets': 'info-exposure',
  'prompt': 'prompt-injection',
  'exfiltration': 'exfiltration',
  'supply': 'supply-chain',
  'command': 'injection',
  'sql': 'injection',
};

/**
 * Extract a unified rule_id from any finding shape.
 */
function extractRuleId(finding) {
  return finding.ruleId || finding.rule_id || finding.id || finding.rule || null;
}

/**
 * Infer category from ruleId when no explicit category is set.
 * Looks at dotted segments of the ruleId for known category keywords.
 */
function inferCategory(ruleId) {
  if (!ruleId) return null;
  const segments = ruleId.toLowerCase().split('.');
  for (const seg of segments) {
    if (RULE_CATEGORY_MAP[seg]) return RULE_CATEGORY_MAP[seg];
  }
  // Check if any segment contains a known keyword
  for (const seg of segments) {
    for (const [key, cat] of Object.entries(RULE_CATEGORY_MAP)) {
      if (seg.includes(key)) return cat;
    }
  }
  return null;
}

/**
 * Normalize confidence to uppercase HIGH/MEDIUM/LOW.
 */
function normalizeConfidence(confidence) {
  if (!confidence) return 'MEDIUM';
  const upper = String(confidence).toUpperCase();
  if (upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW') return upper;
  return 'MEDIUM';
}

/**
 * Normalize action to uppercase BLOCK/WARN/ALLOW or null.
 */
function normalizeAction(action) {
  if (!action) return null;
  const upper = String(action).toUpperCase();
  if (upper === 'BLOCK' || upper === 'WARN' || upper === 'ALLOW') return upper;
  if (upper === 'LOG') return 'WARN';
  return null;
}

/**
 * Normalize a single finding into the internal format.
 *
 * @param {object} finding - Raw finding from any scanner tool
 * @param {string} sourceTool - Tool that produced this finding (fallback if not on finding)
 * @param {object} [options] - Options
 * @param {boolean} [options.includeRaw] - Include original finding as `raw` field
 * @returns {object} Normalized finding
 */
export function normalizeFinding(finding, sourceTool, options = {}) {
  if (!finding || typeof finding !== 'object') {
    return null;
  }

  const originalSeverity = finding.severity || null;
  const mapped = SEVERITY_MAP[originalSeverity] || DEFAULT_SEVERITY;

  const normalized = {
    rule_id: extractRuleId(finding) || 'unknown',
    original_severity: originalSeverity,
    severity: mapped.severity,
    severity_rank: mapped.severity_rank,
    confidence: normalizeConfidence(finding.confidence),
    message: finding.message || '',
    category: finding.category || inferCategory(extractRuleId(finding)),
    cwe: finding.cwe || (finding.metadata && finding.metadata.cwe) || null,
    owasp: finding.owasp || (finding.metadata && finding.metadata.owasp) || null,
    file: finding.file || null,
    line: typeof finding.line === 'number' ? finding.line : null,
    action: normalizeAction(finding.action),
    risk_score: typeof finding.risk_score === 'number'
      ? finding.risk_score
      : (typeof finding.risk_score === 'string' ? parseFloat(finding.risk_score) || null : null),
    source_tool: finding.source_tool || sourceTool || 'unknown',
  };

  if (options.includeRaw) {
    normalized.raw = finding;
  }

  return normalized;
}

/**
 * Normalize an array of findings.
 *
 * @param {object[]} findings - Array of raw findings
 * @param {string} sourceTool - Default source tool (per-finding source_tool wins)
 * @param {object} [options] - Options passed to normalizeFinding
 * @returns {object[]} Array of normalized findings
 */
export function normalizeFindings(findings, sourceTool, options = {}) {
  if (!Array.isArray(findings)) return [];
  return findings
    .map(f => normalizeFinding(f, sourceTool, options))
    .filter(Boolean);
}
