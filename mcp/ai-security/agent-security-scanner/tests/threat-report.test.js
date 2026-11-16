import { describe, it, expect } from 'vitest';
import { normalizeFindings } from '../src/lib/normalize-finding.js';
import { scoreBatch } from '../src/lib/aivss.js';
import { loadControls } from '../src/lib/compliance-controls.js';
import { evaluateAll } from '../src/lib/compliance-evaluator.js';
import { buildThreatModel } from '../src/cli/report.js';
import scanProjectOutput from './fixtures/scan-project-output.json' with { type: 'json' };
import scanPromptOutput from './fixtures/scan-prompt-output.json' with { type: 'json' };
import scanSkillOutput from './fixtures/scan-skill-output.json' with { type: 'json' };

describe('threat-model report integration', () => {
  it('produces valid threat_model JSON from scan_project output', () => {
    const normalized = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const aivssResult = scoreBatch(normalized);

    const controls = loadControls().controls;
    const evidence = {
      aivssPosture: aivssResult.posture,
      findings: normalized,
      grades: { project: scanProjectOutput.grade },
      toolsRun: ['scan_project', 'scan_security'],
    };
    const complianceResult = evaluateAll(controls, evidence);

    // Validate AIVSS output shape
    expect(aivssResult.posture.model.name).toBe('owasp-aivss');
    expect(aivssResult.posture.posture_score).toBeGreaterThanOrEqual(0);
    expect(aivssResult.posture.posture_score).toBeLessThanOrEqual(10);
    expect(aivssResult.findings).toHaveLength(4);
    for (const f of aivssResult.findings) {
      expect(f).toHaveProperty('rule_id');
      expect(f).toHaveProperty('aivss_score');
      expect(f).toHaveProperty('rating');
      expect(f).toHaveProperty('vector_string');
      expect(f.vector_string).toMatch(/^AIVSS:2\.0\//);
    }

    // Validate compliance output shape
    expect(complianceResult.controls_evaluated).toBe(16);
    expect(complianceResult.pass + complianceResult.partial + complianceResult.fail + complianceResult.not_evaluated).toBe(16);
    for (const r of complianceResult.results) {
      expect(r).toHaveProperty('control_id');
      expect(['pass', 'partial', 'fail', 'not_evaluated']).toContain(r.status);
      expect(Array.isArray(r.reasons)).toBe(true);
    }
  });

  it('combines evidence from multiple tool fixtures', () => {
    // Normalize findings from all three fixtures
    const projectFindings = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const promptFindings = normalizeFindings(scanPromptOutput.findings, 'scan_agent_prompt');
    const skillFindings = normalizeFindings(scanSkillOutput.findings, 'scan_skill');

    const allFindings = [...projectFindings, ...promptFindings, ...skillFindings];
    const aivssResult = scoreBatch(allFindings);

    expect(aivssResult.findings).toHaveLength(10); // 4 + 3 + 3

    const controls = loadControls().controls;
    const evidence = {
      aivssPosture: aivssResult.posture,
      findings: allFindings,
      grades: { project: scanProjectOutput.grade, skill: scanSkillOutput.grade },
      toolsRun: ['scan_project', 'scan_security', 'scan_agent_prompt', 'scan_skill'],
    };
    const complianceResult = evaluateAll(controls, evidence);

    // With all tools run, fewer controls should be not_evaluated
    expect(complianceResult.not_evaluated).toBeLessThan(16);
    // Some should now be evaluated (pass/partial/fail)
    expect(complianceResult.pass + complianceResult.partial + complianceResult.fail).toBeGreaterThan(0);
  });

  it('deterministic: same input produces same output', () => {
    const normalized = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const r1 = scoreBatch(normalized);
    const r2 = scoreBatch(normalized);

    expect(r1.posture.posture_score).toBe(r2.posture.posture_score);
    expect(r1.findings.length).toBe(r2.findings.length);
    for (let i = 0; i < r1.findings.length; i++) {
      expect(r1.findings[i].aivss_score).toBe(r2.findings[i].aivss_score);
      expect(r1.findings[i].vector_string).toBe(r2.findings[i].vector_string);
    }
  });

  it('score_aivss tool wrapper produces valid output', async () => {
    const { scoreAivssTool } = await import('../src/tools/score-aivss.js');
    const result = await scoreAivssTool({
      findings: scanProjectOutput.issues,
      source_tool: 'scan_project',
      verbosity: 'compact',
    });

    const output = JSON.parse(result.content[0].text);
    expect(output.findings).toHaveLength(4);
    expect(output.posture).toHaveProperty('posture_score');
    expect(output.posture.aggregate_method).toBe('house-posture-v1');
  });

  it('get_compliance_controls tool wrapper produces valid output', async () => {
    const { getComplianceControls } = await import('../src/tools/compliance-controls.js');
    const result = await getComplianceControls({
      domain: 'security',
      verbosity: 'compact',
    });

    const output = JSON.parse(result.content[0].text);
    expect(output.framework).toBe('AIUC-1');
    expect(output.controls_count).toBe(9); // 9 security controls
    expect(output.controls[0]).toHaveProperty('evaluation');
  });

  it('buildThreatModel produces correct JSON shape from scan_project output', () => {
    const tm = buildThreatModel(scanProjectOutput);

    // AIVSS section
    expect(tm.aivss).toBeTruthy();
    expect(tm.aivss.model.name).toBe('owasp-aivss');
    expect(tm.aivss.posture.posture_score).toBeGreaterThanOrEqual(0);
    expect(tm.aivss.posture.posture_score).toBeLessThanOrEqual(10);
    expect(tm.aivss.posture).toHaveProperty('max_score');
    expect(tm.aivss.posture).toHaveProperty('p95_score');
    expect(tm.aivss.posture).toHaveProperty('mean_score');
    expect(tm.aivss.posture).toHaveProperty('score_distribution');
    expect(tm.aivss.findings).toHaveLength(4);
    for (const f of tm.aivss.findings) {
      expect(f).toHaveProperty('rule_id');
      expect(f).toHaveProperty('aivss_score');
      expect(f).toHaveProperty('rating');
      expect(f).toHaveProperty('vector_string');
      expect(f).toHaveProperty('metrics');
    }

    // Compliance section
    expect(tm.compliance).toBeTruthy();
    expect(tm.compliance.framework).toBe('AIUC-1');
    expect(tm.compliance.controls_evaluated).toBe(16);
    expect(tm.compliance.summary).toHaveProperty('pass');
    expect(tm.compliance.summary).toHaveProperty('partial');
    expect(tm.compliance.summary).toHaveProperty('fail');
    expect(tm.compliance.summary).toHaveProperty('not_evaluated');
    const total = tm.compliance.summary.pass + tm.compliance.summary.partial
      + tm.compliance.summary.fail + tm.compliance.summary.not_evaluated;
    expect(total).toBe(16);
    expect(tm.compliance.results).toHaveLength(16);
  });

  it('buildThreatModel with empty issues produces posture 0', () => {
    const tm = buildThreatModel({ issues: [], grade: 'A' });
    expect(tm.aivss.posture.posture_score).toBe(0);
    expect(tm.aivss.findings).toHaveLength(0);
  });

  it('buildThreatModel: scan_security-scoped controls see findings and grade', () => {
    const tm = buildThreatModel(scanProjectOutput);
    // B004 requires scan_security — should NOT get "No relevant grade"
    const b004 = tm.compliance.results.find(r => r.control_id === 'B004');
    expect(b004).toBeTruthy();
    expect(b004.reasons.every(r => !r.includes('No relevant grade'))).toBe(true);
    // B003 also requires scan_security
    const b003 = tm.compliance.results.find(r => r.control_id === 'B003');
    expect(b003).toBeTruthy();
    expect(b003.reasons.every(r => !r.includes('No relevant grade'))).toBe(true);
  });

  it('compliance evaluation correctly marks not_evaluated controls', () => {
    const normalized = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const aivssResult = scoreBatch(normalized);
    const controls = loadControls().controls;

    // Only scan_project and scan_security run
    const evidence = {
      aivssPosture: aivssResult.posture,
      findings: normalized,
      grades: { project: 'C' },
      toolsRun: ['scan_project', 'scan_security'],
    };
    const result = evaluateAll(controls, evidence);

    // Controls requiring scan_agent_prompt should be not_evaluated
    const promptControls = result.results.filter(r => {
      const ctrl = controls.find(c => c.id === r.control_id);
      return ctrl?.evaluation?.required_tools?.includes('scan_agent_prompt');
    });
    expect(promptControls.length).toBeGreaterThan(0);
    for (const pc of promptControls) {
      expect(pc.status).toBe('not_evaluated');
      expect(pc.reasons[0]).toContain('scan_agent_prompt');
    }
  });
});
