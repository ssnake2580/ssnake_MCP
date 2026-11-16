import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';

describe('inter-procedural taint analysis', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should detect taint flowing through function calls', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-interprocedural.py'),
      verbosity: 'full'
    });
    const issues = result.issues || result.findings || [];
    const taintIssues = issues.filter(i => i.engine === 'taint');
    // processed should be tainted through process_input(cmd)
    const processedTainted = taintIssues.some(i =>
      i.metadata?.tainted_variable === 'processed'
    );
    expect(processedTainted).toBe(true);
  });

  it('should include taint metadata in inter-procedural findings', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-interprocedural.py'),
      verbosity: 'full'
    });
    const issues = result.issues || result.findings || [];
    const taintIssues = issues.filter(i =>
      i.engine === 'taint' && i.metadata?.tainted_variable === 'processed'
    );
    expect(taintIssues.length).toBeGreaterThan(0);
    expect(taintIssues[0].metadata.taint_source).toBeDefined();
    expect(taintIssues[0].metadata.taint_source_line).toBeDefined();
  });
});
