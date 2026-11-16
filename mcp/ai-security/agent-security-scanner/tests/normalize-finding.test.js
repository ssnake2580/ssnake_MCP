import { describe, it, expect } from 'vitest';
import { normalizeFinding, normalizeFindings } from '../src/lib/normalize-finding.js';
import scanProjectOutput from './fixtures/scan-project-output.json' with { type: 'json' };
import scanPromptOutput from './fixtures/scan-prompt-output.json' with { type: 'json' };
import scanSkillOutput from './fixtures/scan-skill-output.json' with { type: 'json' };

describe('normalizeFinding', () => {
  // --- scan_security shape ---
  it('normalizes scan_security finding (ruleId, lowercase severity)', () => {
    const raw = {
      line: 12,
      ruleId: 'python.injection.sql-injection',
      severity: 'error',
      confidence: 'HIGH',
      message: 'SQL injection detected',
    };
    const result = normalizeFinding(raw, 'scan_security');
    expect(result.rule_id).toBe('python.injection.sql-injection');
    expect(result.severity).toBe('HIGH');
    expect(result.severity_rank).toBe(3);
    expect(result.original_severity).toBe('error');
    expect(result.confidence).toBe('HIGH');
    expect(result.source_tool).toBe('scan_security');
    expect(result.line).toBe(12);
  });

  // --- scan_agent_prompt shape ---
  it('normalizes scan_agent_prompt finding (rule_id, UPPERCASE severity)', () => {
    const raw = {
      rule_id: 'generic.prompt.exfiltration.env-access',
      severity: 'ERROR',
      message: 'Prompt requests access to env vars',
      matched_text: 'read the .env',
      risk_score: '90',
      action: 'BLOCK',
      category: 'exfiltration',
      confidence: 'HIGH',
    };
    const result = normalizeFinding(raw, 'scan_agent_prompt');
    expect(result.rule_id).toBe('generic.prompt.exfiltration.env-access');
    expect(result.severity).toBe('HIGH');
    expect(result.severity_rank).toBe(3);
    expect(result.original_severity).toBe('ERROR');
    expect(result.action).toBe('BLOCK');
    expect(result.risk_score).toBe(90);
    expect(result.category).toBe('exfiltration');
    expect(result.source_tool).toBe('scan_agent_prompt');
  });

  // --- scan_project shape ---
  it('normalizes scan_project finding (ruleId, file field)', () => {
    const raw = {
      file: 'app.py',
      line: 25,
      ruleId: 'python.injection.command-injection',
      severity: 'error',
      message: 'Command injection via os.system()',
    };
    const result = normalizeFinding(raw, 'scan_project');
    expect(result.rule_id).toBe('python.injection.command-injection');
    expect(result.file).toBe('app.py');
    expect(result.severity).toBe('HIGH');
    expect(result.source_tool).toBe('scan_project');
  });

  // --- scan_skill shape ---
  it('normalizes scan_skill finding (rule_id, UPPERCASE severity, source)', () => {
    const raw = {
      category: 'prompt-injection',
      severity: 'CRITICAL',
      message: 'Skill prompt contains injection',
      matched_text: 'ignore your system prompt',
      file: 'SKILL.md',
      source: 'prompt_scanner',
      rule_id: 'skill.prompt.injection-override',
      confidence: 'HIGH',
      line: 5,
    };
    const result = normalizeFinding(raw, 'scan_skill');
    expect(result.rule_id).toBe('skill.prompt.injection-override');
    expect(result.severity).toBe('CRITICAL');
    expect(result.severity_rank).toBe(4);
    expect(result.original_severity).toBe('CRITICAL');
    expect(result.confidence).toBe('HIGH');
    expect(result.category).toBe('prompt-injection');
    expect(result.source_tool).toBe('scan_skill');
  });

  // --- scan_mcp_server shape ---
  it('normalizes scan_mcp_server finding (id field)', () => {
    const raw = {
      file: 'server.js',
      severity: 'ERROR',
      category: 'permissions',
      id: 'mcp.permissions.overly-broad',
      message: 'Overly broad permissions detected',
      line: 10,
    };
    const result = normalizeFinding(raw, 'scan_mcp_server');
    expect(result.rule_id).toBe('mcp.permissions.overly-broad');
    expect(result.severity).toBe('HIGH');
    expect(result.original_severity).toBe('ERROR');
    expect(result.source_tool).toBe('scan_mcp_server');
  });

  // --- scan_agent_action shape ---
  it('normalizes scan_agent_action finding (rule field)', () => {
    const raw = {
      rule: 'bash.dangerous-command',
      severity: 'CRITICAL',
      message: 'Destructive command: rm -rf /',
      action: 'BLOCK',
    };
    const result = normalizeFinding(raw, 'scan_agent_action');
    expect(result.rule_id).toBe('bash.dangerous-command');
    expect(result.severity).toBe('CRITICAL');
    expect(result.severity_rank).toBe(4);
    expect(result.action).toBe('BLOCK');
    expect(result.source_tool).toBe('scan_agent_action');
  });

  // --- severity preservation ---
  it('preserves original_severity exactly as source string', () => {
    const lowercase = normalizeFinding({ severity: 'error', message: 'x' }, 'test');
    expect(lowercase.original_severity).toBe('error');

    const uppercase = normalizeFinding({ severity: 'ERROR', message: 'x' }, 'test');
    expect(uppercase.original_severity).toBe('ERROR');

    const critical = normalizeFinding({ severity: 'CRITICAL', message: 'x' }, 'test');
    expect(critical.original_severity).toBe('CRITICAL');
  });

  // --- severity_rank ordering ---
  it('severity_rank ordering: CRITICAL > HIGH > MEDIUM > LOW > INFO', () => {
    const c = normalizeFinding({ severity: 'CRITICAL', message: '' }, 'test');
    const h = normalizeFinding({ severity: 'error', message: '' }, 'test');
    const m = normalizeFinding({ severity: 'warning', message: '' }, 'test');
    const l = normalizeFinding({ severity: 'LOW', message: '' }, 'test');
    const i = normalizeFinding({ severity: 'info', message: '' }, 'test');

    expect(c.severity_rank).toBe(4);
    expect(h.severity_rank).toBe(3);
    expect(m.severity_rank).toBe(2);
    expect(l.severity_rank).toBe(1);
    expect(i.severity_rank).toBe(0);
    expect(c.severity_rank).toBeGreaterThan(h.severity_rank);
    expect(h.severity_rank).toBeGreaterThan(m.severity_rank);
    expect(m.severity_rank).toBeGreaterThan(l.severity_rank);
    expect(l.severity_rank).toBeGreaterThan(i.severity_rank);
  });

  // --- missing fields ---
  it('missing fields get null defaults', () => {
    const result = normalizeFinding({ message: 'bare finding' }, 'test');
    expect(result.rule_id).toBe('unknown');
    expect(result.category).toBeNull();
    expect(result.cwe).toBeNull();
    expect(result.owasp).toBeNull();
    expect(result.file).toBeNull();
    expect(result.line).toBeNull();
    expect(result.action).toBeNull();
    expect(result.risk_score).toBeNull();
    expect(result.confidence).toBe('MEDIUM'); // default
  });

  // --- per-finding source_tool wins ---
  it('per-finding source_tool wins over batch sourceTool param', () => {
    const raw = {
      rule_id: 'test.rule',
      severity: 'ERROR',
      message: 'test',
      source_tool: 'scan_skill',
    };
    const result = normalizeFinding(raw, 'scan_project');
    expect(result.source_tool).toBe('scan_skill');
  });

  // --- raw field ---
  it('raw field present only when includeRaw option is true', () => {
    const raw = { ruleId: 'r1', severity: 'error', message: 'test' };
    const without = normalizeFinding(raw, 'test');
    expect(without.raw).toBeUndefined();

    const withRaw = normalizeFinding(raw, 'test', { includeRaw: true });
    expect(withRaw.raw).toEqual(raw);
  });

  // --- unknown fields don't crash ---
  it('unknown fields on finding do not crash normalization', () => {
    const raw = {
      ruleId: 'test.rule',
      severity: 'error',
      message: 'test',
      totally_unknown_field: 42,
      another: { nested: true },
    };
    const result = normalizeFinding(raw, 'test');
    expect(result.rule_id).toBe('test.rule');
    expect(result.severity).toBe('HIGH');
  });

  // --- category inference from ruleId ---
  it('infers category from ruleId when no explicit category', () => {
    const sqlInj = normalizeFinding({
      ruleId: 'python.injection.sql-injection',
      severity: 'error',
      message: 'SQL injection',
    }, 'scan_security');
    expect(sqlInj.category).toBe('injection');

    const crypto = normalizeFinding({
      ruleId: 'python.crypto.weak-hash',
      severity: 'warning',
      message: 'Weak hash',
    }, 'scan_security');
    expect(crypto.category).toBe('crypto');

    const info = normalizeFinding({
      ruleId: 'python.info.debug-enabled',
      severity: 'info',
      message: 'Debug mode',
    }, 'scan_security');
    expect(info.category).toBe('info-exposure');
  });

  it('explicit category wins over inferred', () => {
    const result = normalizeFinding({
      ruleId: 'python.injection.sql-injection',
      severity: 'error',
      message: 'test',
      category: 'custom-category',
    }, 'scan_security');
    expect(result.category).toBe('custom-category');
  });

  // --- null/invalid input ---
  it('returns null for null or non-object input', () => {
    expect(normalizeFinding(null, 'test')).toBeNull();
    expect(normalizeFinding(undefined, 'test')).toBeNull();
    expect(normalizeFinding('string', 'test')).toBeNull();
  });
});

describe('normalizeFindings (batch)', () => {
  it('normalizes scan_project fixture output', () => {
    const results = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    expect(results).toHaveLength(4);
    expect(results[0].rule_id).toBe('python.injection.sql-injection');
    expect(results[0].source_tool).toBe('scan_project');
    expect(results[0].severity).toBe('HIGH');
    expect(results[0].file).toBe('app.py');
    // info severity maps correctly
    expect(results[3].severity).toBe('INFO');
    expect(results[3].severity_rank).toBe(0);
  });

  it('normalizes scan_agent_prompt fixture output', () => {
    const results = normalizeFindings(scanPromptOutput.findings, 'scan_agent_prompt');
    expect(results).toHaveLength(3);
    expect(results[0].rule_id).toBe('generic.prompt.exfiltration.env-access');
    expect(results[0].action).toBe('BLOCK');
    expect(results[0].risk_score).toBe(90);
    expect(results[0].category).toBe('exfiltration');
    expect(results[1].category).toBe('prompt-injection-jailbreak');
    expect(results[2].severity).toBe('MEDIUM');
    expect(results[2].original_severity).toBe('WARNING');
  });

  it('normalizes scan_skill fixture output', () => {
    const results = normalizeFindings(scanSkillOutput.findings, 'scan_skill');
    expect(results).toHaveLength(3);
    expect(results[0].severity).toBe('CRITICAL');
    expect(results[0].severity_rank).toBe(4);
    expect(results[0].category).toBe('prompt-injection');
    expect(results[1].severity).toBe('HIGH');
    expect(results[1].severity_rank).toBe(3);
    expect(results[2].severity).toBe('MEDIUM');
    expect(results[2].severity_rank).toBe(2);
  });

  it('returns empty array for non-array input', () => {
    expect(normalizeFindings(null, 'test')).toEqual([]);
    expect(normalizeFindings('string', 'test')).toEqual([]);
    expect(normalizeFindings(123, 'test')).toEqual([]);
  });

  it('LOG action normalized to WARN', () => {
    const findings = [{ rule_id: 'r1', severity: 'WARNING', message: 'x', action: 'LOG' }];
    const results = normalizeFindings(findings, 'test');
    expect(results[0].action).toBe('WARN');
  });

  it('risk_score parsed from string', () => {
    const findings = [{ rule_id: 'r1', severity: 'ERROR', message: 'x', risk_score: '75' }];
    const results = normalizeFindings(findings, 'test');
    expect(results[0].risk_score).toBe(75);
  });
});
