import { describe, it, expect, afterEach } from 'vitest';
import { getDaemonClient, shutdownDaemon } from '../src/daemon-client.js';
import { fixturePath } from './helpers.js';

describe('daemon integration', () => {
  afterEach(async () => {
    await shutdownDaemon();
  });

  it('should return healthy from health check', async () => {
    const client = getDaemonClient();
    const result = await client.health();
    expect(result.status).toBe('healthy');
    expect(result.cache_size).toBe(0);
    expect(result.pid).toBeGreaterThan(0);
  });

  it('should analyze a Python file and return issues', async () => {
    const client = getDaemonClient();
    const result = await client.analyze(fixturePath('vuln-python.py'));
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    // Verify issue structure
    const issue = result[0];
    expect(issue).toHaveProperty('ruleId');
    expect(issue).toHaveProperty('severity');
    expect(issue).toHaveProperty('message');
    expect(issue).toHaveProperty('line');
  });

  it('should return error for nonexistent file', async () => {
    const client = getDaemonClient();
    await expect(client.analyze('/nonexistent/file.py')).rejects.toThrow();
  });

  it('should cache results for same file', async () => {
    const client = getDaemonClient();
    // First call populates cache
    await client.analyze(fixturePath('vuln-python.py'));
    // Health shows cache populated
    const health = await client.health();
    expect(health.cache_size).toBeGreaterThan(0);
  });

  it('should shutdown gracefully', async () => {
    const client = getDaemonClient();
    await client.health(); // ensure running
    await client.shutdown();
    expect(client.isAvailable).toBe(true); // not permanently dead
  });
});
