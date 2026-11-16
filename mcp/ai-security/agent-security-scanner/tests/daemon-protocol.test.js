import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'child_process';
import { createInterface } from 'readline';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DAEMON_SCRIPT = join(__dirname, '..', 'daemon.py');

function spawnDaemon() {
  const proc = spawn('python3', [DAEMON_SCRIPT], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
  });
  const rl = createInterface({ input: proc.stdout });
  const messages = [];

  const onMessage = new Promise((resolve) => {
    rl.on('line', (line) => {
      try {
        messages.push(JSON.parse(line));
      } catch { /* skip */ }
    });
    rl.on('close', () => resolve(messages));
  });

  return { proc, rl, messages, onMessage };
}

function waitForMessages(daemon, count, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      resolve(daemon.messages.slice());
    }, timeout);

    const check = setInterval(() => {
      if (daemon.messages.length >= count) {
        clearInterval(check);
        clearTimeout(timer);
        resolve(daemon.messages.slice());
      }
    }, 50);
  });
}

describe('daemon protocol', () => {
  let daemon;

  afterEach(() => {
    if (daemon?.proc && !daemon.proc.killed) {
      try { daemon.proc.kill(); } catch { /* ignore */ }
    }
  });

  it('should send ready signal on startup', async () => {
    daemon = spawnDaemon();
    const msgs = await waitForMessages(daemon, 1);
    expect(msgs[0]).toEqual({
      id: '__ready__',
      success: true,
      result: { status: 'ready' },
    });
    daemon.proc.stdin.write('{"id":"x","action":"shutdown"}\n');
  });

  it('should handle invalid JSON without crashing', async () => {
    daemon = spawnDaemon();
    await waitForMessages(daemon, 1); // wait for ready

    daemon.proc.stdin.write('this is not json\n');
    daemon.proc.stdin.write('{"id":"ok","action":"health"}\n');
    daemon.proc.stdin.write('{"id":"end","action":"shutdown"}\n');

    const msgs = await waitForMessages(daemon, 4);
    // ready + invalid JSON error + health response + shutdown response
    const invalidResp = msgs.find(m => m.id === null && !m.success);
    expect(invalidResp).toBeDefined();
    expect(invalidResp.error).toContain('Invalid JSON');

    const healthResp = msgs.find(m => m.id === 'ok');
    expect(healthResp).toBeDefined();
    expect(healthResp.success).toBe(true);
  });

  it('should return error for unknown action', async () => {
    daemon = spawnDaemon();
    await waitForMessages(daemon, 1); // wait for ready

    daemon.proc.stdin.write('{"id":"unk","action":"foobar"}\n');
    daemon.proc.stdin.write('{"id":"end","action":"shutdown"}\n');

    const msgs = await waitForMessages(daemon, 3);
    const unkResp = msgs.find(m => m.id === 'unk');
    expect(unkResp).toBeDefined();
    expect(unkResp.success).toBe(false);
    expect(unkResp.error).toContain('Unknown action');
  });

  it('should terminate on shutdown action', async () => {
    daemon = spawnDaemon();
    await waitForMessages(daemon, 1); // wait for ready

    daemon.proc.stdin.write('{"id":"bye","action":"shutdown"}\n');

    const msgs = await waitForMessages(daemon, 2);
    const shutdownResp = msgs.find(m => m.id === 'bye');
    expect(shutdownResp).toBeDefined();
    expect(shutdownResp.success).toBe(true);
    expect(shutdownResp.result.status).toBe('shutdown');

    // Process should exit
    await new Promise((resolve) => {
      if (daemon.proc.exitCode !== null) return resolve();
      daemon.proc.on('exit', resolve);
    });
  });
});
