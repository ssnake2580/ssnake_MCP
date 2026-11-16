// src/lib/aivss.js — OWASP AIVSS v2 scoring engine (pure logic, no MCP).

export const AIVSS_MODEL = {
  name: 'owasp-aivss',
  version: 'v2',
  source_ref: 'OWASP/www-project-ai-security@a1b2c3d/calculatorV2.py',
  retrieved: '2026-03-14',
  weights: { base: 0.25, ai_specific: 0.45, impact: 0.30 },
};

export const METRIC_VALUES = {
  AV: { Network: 0.85, Adjacent: 0.62, Local: 0.55, Physical: 0.20 },
  AC: { Low: 0.77, High: 0.44 },
  PR: { None: 0.85, Low: 0.62, High: 0.27 },
  UI: { None: 0.85, Required: 0.62 },
  S: { Unchanged: 1.0, Changed: 1.5 },
  MR: { VeryHigh: 1.0, High: 0.8, Medium: 0.6, Low: 0.4, VeryLow: 0.2 },
  DS: { VeryHigh: 1.0, High: 0.8, Medium: 0.6, Low: 0.4, VeryLow: 0.2 },
  EI: { VeryHigh: 1.0, High: 0.8, Medium: 0.6, Low: 0.4, VeryLow: 0.2 },
  DC: { VeryHigh: 1.0, High: 0.8, Medium: 0.6, Low: 0.4, VeryLow: 0.2 },
  AD: { VeryHigh: 1.0, High: 0.8, Medium: 0.6, Low: 0.4, VeryLow: 0.2 },
  C: { None: 0.0, Low: 0.22, Medium: 0.56, High: 0.85, Critical: 1.0 },
  I: { None: 0.0, Low: 0.22, Medium: 0.56, High: 0.85, Critical: 1.0 },
  A: { None: 0.0, Low: 0.22, Medium: 0.56, High: 0.85, Critical: 1.0 },
  SI: { None: 0.0, Low: 0.22, Medium: 0.56, High: 0.85, Critical: 1.0 },
};

const RATING_THRESHOLDS = [
  { min: 9.0, rating: 'Critical' },
  { min: 7.0, rating: 'High' },
  { min: 4.0, rating: 'Medium' },
  { min: 0.1, rating: 'Low' },
  { min: 0, rating: 'None' },
];

// Category → inferred metric defaults (heuristic)
const CATEGORY_METRIC_MAP = {
  'exfiltration':              { AV: 'Network', MR: 'High', DS: 'High', EI: 'High', C: 'High', SI: 'Medium' },
  'data-exfiltration':         { AV: 'Network', MR: 'High', DS: 'High', EI: 'High', C: 'High', SI: 'Medium' },
  'prompt-injection':          { AV: 'Network', MR: 'VeryHigh', DS: 'Medium', EI: 'High', C: 'Medium', I: 'High' },
  'prompt-injection-jailbreak':{ AV: 'Network', MR: 'VeryHigh', DS: 'High', EI: 'VeryHigh', C: 'Medium', I: 'High', SI: 'High' },
  'prompt-injection-content':  { AV: 'Network', MR: 'High', DS: 'Medium', EI: 'High', C: 'Medium', I: 'Medium' },
  'malicious-injection':       { AV: 'Network', MR: 'High', EI: 'High', C: 'High', I: 'High', A: 'Medium' },
  'system-manipulation':       { AV: 'Local', MR: 'Medium', DC: 'High', C: 'Medium', I: 'High', A: 'High' },
  'social-engineering':        { AV: 'Network', MR: 'Medium', DS: 'Low', EI: 'Medium', C: 'Low', I: 'Medium' },
  'obfuscation':               { AV: 'Network', MR: 'Medium', DC: 'High', EI: 'Medium', C: 'Low', I: 'Medium' },
  'agent-manipulation':        { AV: 'Network', MR: 'High', DS: 'Medium', EI: 'High', C: 'Medium', I: 'High', SI: 'Medium' },
  'injection':                 { AV: 'Network', AC: 'Low', MR: 'Medium', EI: 'Medium', C: 'High', I: 'High' },
  'crypto':                    { AV: 'Network', AC: 'High', MR: 'Low', DS: 'Low', C: 'Medium', I: 'Low' },
  'info-exposure':             { AV: 'Network', AC: 'Low', MR: 'Low', DS: 'Low', C: 'Medium' },
  'permissions':               { AV: 'Local', AC: 'Low', MR: 'Medium', DC: 'Medium', C: 'Medium', I: 'Medium' },
  'supply-chain':              { AV: 'Network', AC: 'High', MR: 'Medium', DS: 'Medium', AD: 'High', C: 'Medium', I: 'High', SI: 'Medium' },
};

// Severity → baseline metric defaults
const SEVERITY_METRIC_MAP = {
  CRITICAL: { AC: 'Low', PR: 'None', UI: 'None', S: 'Changed', DC: 'Medium', AD: 'Medium', A: 'High' },
  HIGH:     { AC: 'Low', PR: 'None', UI: 'None', S: 'Unchanged', DC: 'Low', AD: 'Low', A: 'Medium' },
  MEDIUM:   { AC: 'High', PR: 'Low', UI: 'None', S: 'Unchanged', DC: 'Low', AD: 'Low', A: 'Low' },
  LOW:      { AC: 'High', PR: 'Low', UI: 'Required', S: 'Unchanged', DC: 'VeryLow', AD: 'VeryLow', A: 'None' },
  INFO:     { AC: 'High', PR: 'High', UI: 'Required', S: 'Unchanged', DC: 'VeryLow', AD: 'VeryLow', A: 'None' },
};

// All metric keys in vector string order
const ALL_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'MR', 'DS', 'EI', 'DC', 'AD', 'C', 'I', 'A', 'SI'];

// Default values for all metrics
const METRIC_DEFAULTS = {
  AV: 'Network', AC: 'Low', PR: 'None', UI: 'None', S: 'Unchanged',
  MR: 'Medium', DS: 'Medium', EI: 'Medium', DC: 'Medium', AD: 'Medium',
  C: 'Low', I: 'Low', A: 'Low', SI: 'Low',
};

/**
 * Compute raw AIVSS score from metric values.
 * @param {object} metrics - Object with keys AV, AC, PR, UI, S, MR, DS, EI, DC, AD, C, I, A, SI
 * @returns {{ score: number, components: { base: number, ai_specific: number, impact: number } }}
 */
export function computeAivss(metrics) {
  const mv = (key) => {
    const val = metrics[key];
    const table = METRIC_VALUES[key];
    if (!table || !(val in table)) return 0;
    return table[val];
  };

  // Base = min(AV × AC × PR × UI × S, 10)
  const baseRaw = mv('AV') * mv('AC') * mv('PR') * mv('UI') * mv('S');
  const base = Math.min(baseRaw, 10);

  // AI-Specific = MR × DS × EI × DC × AD × 10
  const aiSpecific = mv('MR') * mv('DS') * mv('EI') * mv('DC') * mv('AD') * 10;

  // Impact = (C + I + A + SI) / 4 × 10
  const impact = (mv('C') + mv('I') + mv('A') + mv('SI')) / 4 * 10;

  // AIVSS = 0.25 × Base + 0.45 × AI-Specific + 0.30 × Impact
  const score = 0.25 * base + 0.45 * aiSpecific + 0.30 * impact;

  return {
    score: Math.min(10, Math.max(0, parseFloat(score.toFixed(2)))),
    components: {
      base: parseFloat(base.toFixed(4)),
      ai_specific: parseFloat(aiSpecific.toFixed(4)),
      impact: parseFloat(impact.toFixed(4)),
    },
  };
}

/**
 * Get AIVSS rating string from score.
 */
function getRating(score) {
  for (const t of RATING_THRESHOLDS) {
    if (score >= t.min) return t.rating;
  }
  return 'None';
}

/**
 * Build vector string from final metrics.
 */
function buildVectorString(metrics) {
  const parts = ALL_METRICS.map(k => {
    const val = metrics[k] || METRIC_DEFAULTS[k];
    // Abbreviate: first letter, or first 2 for disambiguation
    const abbrev = val === 'VeryHigh' ? 'VH'
      : val === 'VeryLow' ? 'VL'
      : val === 'Adjacent' ? 'A'
      : val === 'Physical' ? 'P'
      : val === 'Required' ? 'R'
      : val === 'Changed' ? 'C'
      : val === 'Unchanged' ? 'U'
      : val === 'Critical' ? 'CR'
      : val.charAt(0);
    return `${k}:${abbrev}`;
  });
  return `AIVSS:2.0/${parts.join('/')}`;
}

/**
 * Infer AIVSS metrics from a normalized finding. Returns inferred metrics + notes.
 */
function inferMetrics(finding) {
  const notes = [];
  const inferred = { ...METRIC_DEFAULTS };

  // Layer 1: severity-based defaults
  const sevMap = SEVERITY_METRIC_MAP[finding.severity] || SEVERITY_METRIC_MAP.MEDIUM;
  Object.assign(inferred, sevMap);
  notes.push(`Baseline metrics from severity: ${finding.severity}`);

  // Layer 2: category-based overrides
  if (finding.category && CATEGORY_METRIC_MAP[finding.category]) {
    const catMap = CATEGORY_METRIC_MAP[finding.category];
    Object.assign(inferred, catMap);
    notes.push(`Category-specific metrics from: ${finding.category}`);
  }

  // Layer 3: confidence adjustment
  if (finding.confidence === 'LOW') {
    // Reduce AI-specific metrics for low confidence
    for (const k of ['MR', 'DS', 'EI']) {
      if (inferred[k] === 'VeryHigh') inferred[k] = 'High';
      else if (inferred[k] === 'High') inferred[k] = 'Medium';
    }
    notes.push('AI-specific metrics reduced due to LOW confidence');
  }

  // Determine mapping confidence
  let mappingConfidence = 'MEDIUM';
  if (finding.category && CATEGORY_METRIC_MAP[finding.category] && finding.confidence === 'HIGH') {
    mappingConfidence = 'HIGH';
  } else if (!finding.category || finding.confidence === 'LOW') {
    mappingConfidence = 'LOW';
  }

  return { inferred, notes, mappingConfidence };
}

/**
 * Score a single normalized finding.
 * @param {object} normalizedFinding - Output of normalizeFinding()
 * @param {object} [overrides] - Manual AIVSS metric overrides
 * @returns {object} Scored finding
 */
export function scoreAivss(normalizedFinding, overrides = {}) {
  const { inferred, notes, mappingConfidence } = inferMetrics(normalizedFinding);

  // Merge: overrides win
  const final = { ...inferred };
  const overriddenKeys = {};
  for (const [key, val] of Object.entries(overrides)) {
    if (ALL_METRICS.includes(key) && METRIC_VALUES[key] && val in METRIC_VALUES[key]) {
      overriddenKeys[key] = val;
      final[key] = val;
      notes.push(`${key} overridden to ${val}`);
    }
  }

  const { score, components } = computeAivss(final);

  return {
    rule_id: normalizedFinding.rule_id,
    aivss_score: score,
    rating: getRating(score),
    vector_string: buildVectorString(final),
    metrics: {
      inferred,
      overridden: Object.keys(overriddenKeys).length > 0 ? overriddenKeys : undefined,
      final,
      mapping_confidence: mappingConfidence,
      mapping_notes: notes,
    },
    components,
  };
}

/**
 * Score a batch of normalized findings and compute aggregate posture.
 * @param {object[]} normalizedFindings - Array of normalized findings
 * @param {object} [overrides] - Overrides applied to all findings
 * @returns {{ findings: object[], posture: object }}
 */
export function scoreBatch(normalizedFindings, overrides = {}) {
  if (!normalizedFindings || normalizedFindings.length === 0) {
    return {
      findings: [],
      posture: {
        max_score: 0,
        p95_score: 0,
        mean_score: 0,
        score_distribution: { critical: 0, high: 0, medium: 0, low: 0, none: 0 },
        posture_score: 0,
        posture_rating: 'None',
        aggregate_method: 'house-posture-v1',
        aggregate_note: 'Custom aggregation: max(max_score, mean + 1σ). Per-finding AIVSS scores are standards-based; this aggregate is not.',
        model: AIVSS_MODEL,
      },
    };
  }

  const scored = normalizedFindings.map(f => scoreAivss(f, overrides));
  const scores = scored.map(s => s.aivss_score).sort((a, b) => a - b);

  const max_score = scores[scores.length - 1];
  const mean_score = parseFloat((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(2));

  // P95
  const p95Idx = Math.min(Math.ceil(scores.length * 0.95) - 1, scores.length - 1);
  const p95_score = scores[p95Idx];

  // Standard deviation
  const variance = scores.reduce((sum, s) => sum + Math.pow(s - mean_score, 2), 0) / scores.length;
  const stdDev = Math.sqrt(variance);

  // Posture = max(max_score, mean + 1σ), capped at 10
  const posture_score = parseFloat(Math.min(10, Math.max(max_score, mean_score + stdDev)).toFixed(2));

  // Distribution
  const score_distribution = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  for (const s of scores) {
    if (s >= 9) score_distribution.critical++;
    else if (s >= 7) score_distribution.high++;
    else if (s >= 4) score_distribution.medium++;
    else if (s >= 0.1) score_distribution.low++;
    else score_distribution.none++;
  }

  return {
    findings: scored,
    posture: {
      max_score,
      p95_score,
      mean_score,
      score_distribution,
      posture_score,
      posture_rating: getRating(posture_score),
      aggregate_method: 'house-posture-v1',
      aggregate_note: 'Custom aggregation: max(max_score, mean + 1σ). Per-finding AIVSS scores are standards-based; this aggregate is not.',
      model: AIVSS_MODEL,
    },
  };
}
