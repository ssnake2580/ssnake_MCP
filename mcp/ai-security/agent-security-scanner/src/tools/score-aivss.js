// src/tools/score-aivss.js — score_aivss MCP tool (thin wrapper around src/lib/aivss.js)

import { z } from 'zod';
import { normalizeFindings } from '../lib/normalize-finding.js';
import { scoreBatch, AIVSS_MODEL } from '../lib/aivss.js';

export const scoreAivssSchema = {
  findings: z.array(z.object({
    ruleId: z.string().optional(),
    rule_id: z.string().optional(),
    id: z.string().optional(),
    rule: z.string().optional(),
    severity: z.string(),
    message: z.string(),
    confidence: z.string().optional(),
    category: z.string().optional(),
    cwe: z.string().optional(),
    owasp: z.string().optional(),
    risk_score: z.union([z.number(), z.string()]).optional(),
    action: z.string().optional(),
    file: z.string().optional(),
    line: z.number().optional(),
    source_tool: z.string().optional(),
  })).describe('Findings from any scanner tool or raw JSON'),
  source_tool: z.string().optional().describe('Tool that produced findings, for normalization hints'),
  overrides: z.object({
    AV: z.string().optional(),
    AC: z.string().optional(),
    PR: z.string().optional(),
    UI: z.string().optional(),
    S: z.string().optional(),
    MR: z.string().optional(),
    DS: z.string().optional(),
    EI: z.string().optional(),
    DC: z.string().optional(),
    AD: z.string().optional(),
    C: z.string().optional(),
    I: z.string().optional(),
    A: z.string().optional(),
    SI: z.string().optional(),
  }).optional().describe('Manual AIVSS metric overrides'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level"),
};

export async function scoreAivssTool({ findings, source_tool, overrides, verbosity }) {
  const level = verbosity || 'compact';

  const normalized = normalizeFindings(findings, source_tool || 'unknown', {
    includeRaw: level === 'full',
  });

  const result = scoreBatch(normalized, overrides || {});

  let output;
  switch (level) {
    case 'minimal':
      output = {
        findings_count: result.findings.length,
        posture_score: result.posture.posture_score,
        posture_rating: result.posture.posture_rating,
        aggregate_method: result.posture.aggregate_method,
      };
      break;

    case 'full':
      output = {
        findings: result.findings,
        posture: result.posture,
      };
      break;

    case 'compact':
    default:
      output = {
        findings: result.findings.map(f => ({
          rule_id: f.rule_id,
          aivss_score: f.aivss_score,
          rating: f.rating,
          vector_string: f.vector_string,
          mapping_confidence: f.metrics.mapping_confidence,
        })),
        posture: {
          posture_score: result.posture.posture_score,
          posture_rating: result.posture.posture_rating,
          max_score: result.posture.max_score,
          score_distribution: result.posture.score_distribution,
          aggregate_method: result.posture.aggregate_method,
        },
      };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(output, null, 2),
    }],
  };
}
