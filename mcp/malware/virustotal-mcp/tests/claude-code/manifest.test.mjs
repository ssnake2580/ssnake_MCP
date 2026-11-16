// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const pluginRoot = 'plugins/claude-code';
const json = async (filename) => JSON.parse(await readFile(path.join(root, filename), 'utf8'));

// The submitted directory is intentionally declarative. Any additional file,
// including a hidden hook or renamed program, needs an explicit package review.
const packagedFiles = [
  '.claude-plugin/icon.png',
  '.claude-plugin/plugin.json',
  '.mcp.json',
  'README.md',
  'skills/threat-intelligence/SKILL.md',
];

async function inventory(relative = '') {
  const found = [];
  for (const name of await readdir(path.join(root, pluginRoot, relative))) {
    const item = path.posix.join(relative, name);
    const info = await lstat(path.join(root, pluginRoot, item));
    assert.equal(info.isSymbolicLink(), false, `Unexpected link: ${item}`);
    assert.ok(info.isDirectory() || info.isFile(), `Not a regular entry: ${item}`);
    if (info.isDirectory()) found.push(...await inventory(item));
    else found.push(item);
  }
  return found.sort();
}

test('marketplace resolves to the versioned plugin and credential-free HTTPS MCP server', async () => {
  const marketplace = await json('.claude-plugin/marketplace.json');
  const manifest = await json(`${pluginRoot}/.claude-plugin/plugin.json`);
  const contract = await json('src/vt_mcp/client_contracts.json');
  assert.equal(marketplace.plugins[0].source, `./${pluginRoot}`);
  assert.equal(manifest.version, contract.claude_code.plugin_version);
  assert.equal(marketplace.name, 'virustotal');
  assert.equal(marketplace.plugins[0].name, manifest.name);
  assert.equal(manifest.name, 'virustotal');
  assert.equal(manifest.license, 'Apache-2.0');
  assert.equal('hooks' in manifest, false);
  assert.equal('hooks' in marketplace.plugins[0], false);
  assert.deepEqual(await json(`${pluginRoot}/.mcp.json`), {
    virustotal: { type: 'http', url: 'https://ai.virustotal.com/mcp' },
  });
});

test('submitted directory contains only reviewed metadata, skill, README and PNG', async () => {
  assert.deepEqual(await inventory(), packagedFiles);
  for (const name of packagedFiles) {
    const bytes = await readFile(path.join(root, pluginRoot, name));
    assert.ok(bytes.length > 0 && bytes.length < 256 * 1024, name);
    if (name.endsWith('.png')) {
      assert.deepEqual([...bytes.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
      continue;
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    assert.equal(text.includes('\0'), false, name);
    assert.equal(text.startsWith('#!'), false, name);
    assert.doesNotMatch(text, /!`[^`]+`/, `Dynamic command in ${name}`);
    if (name.endsWith('.json')) JSON.parse(text);
  }
  const readme = await readFile(path.join(root, pluginRoot, 'README.md'), 'utf8');
  assert.ok(readme.replace(/```[\s\S]*?```/g, '').split(/\s+/).length >= 40);
});
