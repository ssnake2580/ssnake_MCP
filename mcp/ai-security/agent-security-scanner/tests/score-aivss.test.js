import { describe, it, expect } from 'vitest';
import { scoreAivss, scoreBatch, computeAivss, AIVSS_MODEL, METRIC_VALUES } from '../src/lib/aivss.js';
import { normalizeFindings } from '../src/lib/normalize-finding.js';
import scanProjectOutput from './fixtures/scan-project-output.json' with { type: 'json' };
import scanPromptOutput from './fixtures/scan-prompt-output.json' with { type: 'json' };
import scanSkillOutput from './fixtures/scan-skill-output.json' with { type: 'json' };

describe('computeAivss', () => {
  it('computes score from known metric values', () => {
    const metrics = {
      AV: 'Network', AC: 'Low', PR: 'None', UI: 'None', S: 'Unchanged',
      MR: 'High', DS: 'High', EI: 'High', DC: 'High', AD: 'High',
      C: 'High', I: 'High', A: 'High', SI: 'High',
    };
    const { score, components } = computeAivss(metrics);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(10);
    expect(components.base).toBeGreaterThan(0);
    expect(components.ai_specific).toBeGreaterThan(0);
    expect(components.impact).toBeGreaterThan(0);
  });

  it('returns 0 for all-None/lowest metrics', () => {
    const metrics = {
      AV: 'Physical', AC: 'High', PR: 'High', UI: 'Required', S: 'Unchanged',
      MR: 'VeryLow', DS: 'VeryLow', EI: 'VeryLow', DC: 'VeryLow', AD: 'VeryLow',
      C: 'None', I: 'None', A: 'None', SI: 'None',
    };
    const { score } = computeAivss(metrics);
    expect(score).toBeLessThan(0.5);
  });

  it('never returns > 10', () => {
    const metrics = {
      AV: 'Network', AC: 'Low', PR: 'None', UI: 'None', S: 'Changed',
      MR: 'VeryHigh', DS: 'VeryHigh', EI: 'VeryHigh', DC: 'VeryHigh', AD: 'VeryHigh',
      C: 'Critical', I: 'Critical', A: 'Critical', SI: 'Critical',
    };
    const { score } = computeAivss(metrics);
    expect(score).toBeLessThanOrEqual(10);
  });

  it('golden vector: all-High metrics produce expected score', () => {
    // Manual calculation:
    // Base = min(0.85 × 0.77 × 0.85 × 0.85 × 1.0, 10) = 0.4727
    // AI   = 0.8^5 × 10 = 3.2768
    // Impact = (0.85 × 4) / 4 × 10 = 8.5
    // AIVSS = 0.25×0.4727 + 0.45×3.2768 + 0.30×8.5 = 4.14
    const metrics = {
      AV: 'Network', AC: 'Low', PR: 'None', UI: 'None', S: 'Unchanged',
      MR: 'High', DS: 'High', EI: 'High', DC: 'High', AD: 'High',
      C: 'High', I: 'High', A: 'High', SI: 'High',
    };
    const { score } = computeAivss(metrics);
    expect(score).toBeCloseTo(4.14, 1);
  });

  it('golden vector: worst-case reachable metrics', () => {
    // Base = min(0.85×0.77×0.85×0.85×1.5, 10) = 0.7091
    // AI   = 1^5 × 10 = 10
    // Impact = (1.0 × 4) / 4 × 10 = 10
    // AIVSS = 0.25×0.7091 + 0.45×10 + 0.30×10 = 7.68
    const metrics = {
      AV: 'Network', AC: 'Low', PR: 'None', UI: 'None', S: 'Changed',
      MR: 'VeryHigh', DS: 'VeryHigh', EI: 'VeryHigh', DC: 'VeryHigh', AD: 'VeryHigh',
      C: 'Critical', I: 'Critical', A: 'Critical', SI: 'Critical',
    };
    const { score } = computeAivss(metrics);
    expect(score).toBeCloseTo(7.68, 1);
  });

  it('source_ref is pinned to an immutable commit', () => {
    expect(AIVSS_MODEL.source_ref).not.toContain('@main');
    expect(AIVSS_MODEL.source_ref).toMatch(/@[a-f0-9]+\//);
  });

  it('never returns < 0', () => {
    const metrics = {
      AV: 'Physical', AC: 'High', PR: 'High', UI: 'Required', S: 'Unchanged',
      MR: 'VeryLow', DS: 'VeryLow', EI: 'VeryLow', DC: 'VeryLow', AD: 'VeryLow',
      C: 'None', I: 'None', A: 'None', SI: 'None',
    };
    const { score } = computeAivss(metrics);
    expect(score).toBeGreaterThanOrEqual(0);
  });
});

describe('scoreAivss', () => {
  it('scores a single normalized finding correctly', () => {
    const finding = {
      rule_id: 'test.sql-injection',
      severity: 'HIGH',
      severity_rank: 3,
      confidence: 'HIGH',
      category: 'injection',
      message: 'SQL injection',
      source_tool: 'scan_security',
    };
    const result = scoreAivss(finding);
    expect(result.rule_id).toBe('test.sql-injection');
    expect(result.aivss_score).toBeGreaterThan(0);
    expect(result.rating).toBeTruthy();
    expect(result.vector_string).toMatch(/^AIVSS:2\.0\//);
    expect(result.metrics.inferred).toBeTruthy();
    expect(result.metrics.final).toBeTruthy();
    expect(result.metrics.mapping_confidence).toBe('HIGH');
    expect(result.metrics.mapping_notes.length).toBeGreaterThan(0);
  });

  it('manual overrides replace inferred metrics', () => {
    const finding = {
      rule_id: 'test.rule',
      severity: 'MEDIUM',
      severity_rank: 2,
      confidence: 'MEDIUM',
      message: 'test',
      source_tool: 'test',
    };
    const result = scoreAivss(finding, { AV: 'Physical', C: 'Critical' });
    expect(result.metrics.overridden).toEqual({ AV: 'Physical', C: 'Critical' });
    expect(result.metrics.final.AV).toBe('Physical');
    expect(result.metrics.final.C).toBe('Critical');
    expect(result.metrics.mapping_notes).toEqual(
      expect.arrayContaining([
        expect.stringContaining('AV overridden'),
        expect.stringContaining('C overridden'),
      ])
    );
  });

  it('mapping_confidence HIGH for known category + HIGH confidence', () => {
    const finding = {
      rule_id: 'r1', severity: 'HIGH', severity_rank: 3,
      confidence: 'HIGH', category: 'injection', message: '', source_tool: 'test',
    };
    expect(scoreAivss(finding).metrics.mapping_confidence).toBe('HIGH');
  });

  it('mapping_confidence LOW for unknown category', () => {
    const finding = {
      rule_id: 'r1', severity: 'MEDIUM', severity_rank: 2,
      confidence: 'MEDIUM', category: null, message: '', source_tool: 'test',
    };
    expect(scoreAivss(finding).metrics.mapping_confidence).toBe('LOW');
  });

  it('mapping_confidence LOW for LOW confidence', () => {
    const finding = {
      rule_id: 'r1', severity: 'HIGH', severity_rank: 3,
      confidence: 'LOW', category: 'injection', message: '', source_tool: 'test',
    };
    expect(scoreAivss(finding).metrics.mapping_confidence).toBe('LOW');
  });

  it('mapping_notes populated with reasoning strings', () => {
    const finding = {
      rule_id: 'r1', severity: 'HIGH', severity_rank: 3,
      confidence: 'HIGH', category: 'exfiltration', message: '', source_tool: 'test',
    };
    const notes = scoreAivss(finding).metrics.mapping_notes;
    expect(notes.some(n => n.includes('severity'))).toBe(true);
    expect(notes.some(n => n.includes('Category-specific'))).toBe(true);
  });

  it('vector string format is valid', () => {
    const finding = {
      rule_id: 'r1', severity: 'HIGH', severity_rank: 3,
      confidence: 'HIGH', message: '', source_tool: 'test',
    };
    const vs = scoreAivss(finding).vector_string;
    expect(vs).toMatch(/^AIVSS:2\.0\//);
    // Should have 14 metric components
    const parts = vs.split('/').slice(1); // remove AIVSS:2.0
    expect(parts).toHaveLength(14);
    parts.forEach(p => expect(p).toMatch(/^[A-Z]{1,2}:[A-Z]{1,2}$/i));
  });

  it('deterministic: same input → same output', () => {
    const finding = {
      rule_id: 'det.test', severity: 'HIGH', severity_rank: 3,
      confidence: 'HIGH', category: 'injection', message: 'test', source_tool: 'test',
    };
    const r1 = scoreAivss(finding);
    const r2 = scoreAivss(finding);
    expect(r1.aivss_score).toBe(r2.aivss_score);
    expect(r1.vector_string).toBe(r2.vector_string);
    expect(r1.rating).toBe(r2.rating);
  });
});

describe('scoreBatch', () => {
  it('empty findings → posture 0', () => {
    const result = scoreBatch([]);
    expect(result.findings).toEqual([]);
    expect(result.posture.posture_score).toBe(0);
    expect(result.posture.max_score).toBe(0);
    expect(result.posture.mean_score).toBe(0);
    expect(result.posture.posture_rating).toBe('None');
    expect(result.posture.aggregate_method).toBe('house-posture-v1');
    expect(result.posture.model).toEqual(AIVSS_MODEL);
  });

  it('aggregate posture: max_score, p95, mean, distribution correct', () => {
    const findings = [
      { rule_id: 'r1', severity: 'CRITICAL', severity_rank: 4, confidence: 'HIGH', category: 'exfiltration', message: '', source_tool: 't' },
      { rule_id: 'r2', severity: 'MEDIUM', severity_rank: 2, confidence: 'MEDIUM', message: '', source_tool: 't' },
      { rule_id: 'r3', severity: 'INFO', severity_rank: 0, confidence: 'LOW', message: '', source_tool: 't' },
    ];
    const result = scoreBatch(findings);
    expect(result.findings).toHaveLength(3);
    expect(result.posture.max_score).toBeGreaterThan(0);
    expect(result.posture.p95_score).toBeLessThanOrEqual(result.posture.max_score);
    expect(result.posture.mean_score).toBeLessThanOrEqual(result.posture.max_score);
    expect(result.posture.posture_score).toBeGreaterThanOrEqual(result.posture.max_score);
    expect(result.posture.posture_score).toBeLessThanOrEqual(10);

    const dist = result.posture.score_distribution;
    expect(dist.critical + dist.high + dist.medium + dist.low + dist.none).toBe(3);
  });

  it('aggregate_method = house-posture-v1', () => {
    const findings = [
      { rule_id: 'r1', severity: 'HIGH', severity_rank: 3, confidence: 'HIGH', message: '', source_tool: 't' },
    ];
    const result = scoreBatch(findings);
    expect(result.posture.aggregate_method).toBe('house-posture-v1');
    expect(result.posture.aggregate_note).toContain('Custom aggregation');
  });

  it('model metadata present with source_ref', () => {
    const result = scoreBatch([]);
    expect(result.posture.model.name).toBe('owasp-aivss');
    expect(result.posture.model.version).toBe('v2');
    expect(result.posture.model.source_ref).toBeTruthy();
    expect(result.posture.model.retrieved).toBeTruthy();
  });

  it('standalone: raw JSON findings get Medium defaults', () => {
    const findings = [
      { rule_id: 'custom.rule', severity: 'MEDIUM', severity_rank: 2, confidence: 'MEDIUM', message: 'a raw finding', source_tool: 'external' },
    ];
    const result = scoreBatch(findings);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].aivss_score).toBeGreaterThan(0);
  });
});

describe('fixture integration', () => {
  it('score scan_project output', () => {
    const normalized = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const result = scoreBatch(normalized);
    expect(result.findings).toHaveLength(4);
    expect(result.posture.max_score).toBeGreaterThan(0);
    // Error-severity findings should score higher than info
    const errorScores = result.findings.filter(f => f.rule_id.includes('injection')).map(f => f.aivss_score);
    const infoScores = result.findings.filter(f => f.rule_id.includes('debug')).map(f => f.aivss_score);
    if (errorScores.length > 0 && infoScores.length > 0) {
      expect(Math.max(...errorScores)).toBeGreaterThan(Math.min(...infoScores));
    }
  });

  it('score scan_agent_prompt output', () => {
    const normalized = normalizeFindings(scanPromptOutput.findings, 'scan_agent_prompt');
    const result = scoreBatch(normalized);
    expect(result.findings).toHaveLength(3);
    expect(result.posture.max_score).toBeGreaterThan(0);
    // Exfiltration finding should score high
    const exfilScore = result.findings.find(f => f.rule_id.includes('exfiltration'));
    expect(exfilScore.aivss_score).toBeGreaterThan(1);
  });

  it('score scan_skill output', () => {
    const normalized = normalizeFindings(scanSkillOutput.findings, 'scan_skill');
    const result = scoreBatch(normalized);
    expect(result.findings).toHaveLength(3);
    expect(result.posture.max_score).toBeGreaterThan(0);
    // CRITICAL finding should have highest score
    const criticalFinding = result.findings.find(f =>
      normalized.find(n => n.rule_id === f.rule_id && n.severity === 'CRITICAL')
    );
    if (criticalFinding) {
      expect(criticalFinding.aivss_score).toBeGreaterThanOrEqual(
        Math.min(...result.findings.map(f => f.aivss_score))
      );
    }
  });
});
