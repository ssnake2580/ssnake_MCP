const {spawn} = require('node:child_process');
const path = require('node:path');

module.exports = class VolPilotProvider {
  id() { return 'volpilot-qwen-live'; }
  async callApi(prompt, context) {
    return new Promise((resolve, reject) => {
      const project = path.resolve(__dirname, '../../..');
      const child = spawn(process.env.RQ4_UV || 'uv',
        ['run', '--no-sync', '--offline', 'python', path.join(__dirname, 'harness.py')],
        {cwd: project, env: {...process.env,
          UV_CACHE_DIR: path.join(__dirname, '.cache/uv'),
          XDG_CACHE_HOME: path.join(__dirname, '.cache/xdg')}});
      let stdout = '', stderr = '';
      child.stdout.on('data', x => stdout += x);
      child.stderr.on('data', x => stderr += x);
      child.on('error', reject);
      child.on('close', code => {
        if (code !== 0) return resolve({error: `Harness exited ${code}: ${stderr.slice(-1500)}`});
        try { resolve(JSON.parse(stdout)); }
        catch (e) { resolve({error: `Invalid harness result: ${e.message}`}); }
      });
      child.stdin.end(JSON.stringify({prompt, case_id: context.vars.case_id}));
    });
  }
};
