#!/usr/bin/env node
// scripts/benchmark-daemon.js — Measure scan throughput: daemon (cold/warm) vs sync fallback.

import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { execFileSync } from 'child_process';
import { performance } from 'perf_hooks';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ANALYZER_PATH = join(__dirname, '..', 'analyzer.py');

const FILE_COUNT = 100;

// Vulnerability patterns to spread across generated files
const VULN_TEMPLATES = [
  // SQL injection
  `const query = "SELECT * FROM users WHERE id = " + req.params.id;
db.query(query);`,
  // Command injection
  `const { exec } = require('child_process');
exec("ls " + userInput);`,
  // XSS
  `document.innerHTML = '<div>' + userData + '</div>';`,
  // Path traversal
  `const filePath = './uploads/' + req.query.filename;
fs.readFileSync(filePath);`,
  // Hardcoded secret
  `const API_KEY = "sk-live-abc123secret456";
fetch(url, { headers: { Authorization: API_KEY } });`,
  // Eval
  `const result = eval(req.body.expression);`,
  // Insecure random
  `const token = Math.random().toString(36);`,
  // Open redirect
  `res.redirect(req.query.url);`,
  // Prototype pollution
  `function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}`,
  // NoSQL injection
  `db.collection('users').find({ username: req.body.username, password: req.body.password });`,
];

function generateFiles(dir) {
  const files = [];
  for (let i = 0; i < FILE_COUNT; i++) {
    const template = VULN_TEMPLATES[i % VULN_TEMPLATES.length];
    const filePath = join(dir, `test_${i}.js`);
    writeFileSync(filePath, `// Generated benchmark file ${i}\n${template}\n`);
    files.push(filePath);
  }
  return files;
}

async function benchmarkDaemon(files, label) {
  // Dynamic import to avoid top-level side effects
  const { runAnalyzerAsync } = await import('../src/utils.js');

  const start = performance.now();
  for (const f of files) {
    await runAnalyzerAsync(f);
  }
  const elapsed = performance.now() - start;
  return { label, elapsed, perFile: elapsed / files.length };
}

function benchmarkSync(files) {
  const start = performance.now();
  for (const f of files) {
    try {
      execFileSync('python3', [ANALYZER_PATH, f], {
        encoding: 'utf-8',
        timeout: 30000,
      });
    } catch {
      // ignore errors — measuring throughput
    }
  }
  const elapsed = performance.now() - start;
  return { label: 'Sync fallback', elapsed, perFile: elapsed / files.length };
}

function fmt(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${ms.toFixed(0)}ms`;
}

function fmtPerFile(ms) {
  return `${ms.toFixed(0)}ms`;
}

async function main() {
  console.log('=== Daemon Benchmark ===');
  console.log(`Files: ${FILE_COUNT}\n`);

  // Create temp dir with test files
  const tmpDir = mkdtempSync(join(tmpdir(), 'scanner-bench-'));
  const files = generateFiles(tmpDir);

  try {
    // Run 1: Daemon cold cache
    console.log('Running daemon (cold cache)...');
    const cold = await benchmarkDaemon(files, 'Daemon (cold)');
    console.log(`  ${cold.label}: ${fmt(cold.elapsed)} (${fmtPerFile(cold.perFile)}/file)`);

    // Run 2: Daemon warm cache
    console.log('Running daemon (warm cache)...');
    const warm = await benchmarkDaemon(files, 'Daemon (warm)');
    console.log(`  ${warm.label}: ${fmt(warm.elapsed)} (${fmtPerFile(warm.perFile)}/file)`);

    const warmVsCold = cold.elapsed / warm.elapsed;
    console.log(`  ${warmVsCold.toFixed(1)}x speedup over cold\n`);

    // Run 3: Sync fallback (shutdown daemon first)
    console.log('Running sync fallback...');
    const { shutdownDaemon } = await import('../src/utils.js');
    await shutdownDaemon();

    const sync = benchmarkSync(files);
    console.log(`  ${sync.label}: ${fmt(sync.elapsed)} (${fmtPerFile(sync.perFile)}/file)\n`);

    // Summary
    const coldSpeedup = sync.elapsed / cold.elapsed;
    const warmSpeedup = sync.elapsed / warm.elapsed;

    console.log('=== Summary ===');
    console.log(`Daemon (cold):   ${fmt(cold.elapsed).padStart(8)} (${fmtPerFile(cold.perFile)}/file)`);
    console.log(`Daemon (warm):   ${fmt(warm.elapsed).padStart(8)} (${fmtPerFile(warm.perFile)}/file)  — ${warmVsCold.toFixed(1)}x speedup over cold`);
    console.log(`Sync fallback:   ${fmt(sync.elapsed).padStart(8)} (${fmtPerFile(sync.perFile)}/file)`);
    console.log(`Daemon speedup:  ${coldSpeedup.toFixed(1)}x (cold) / ${warmSpeedup.toFixed(1)}x (warm) vs sync`);
  } finally {
    // Cleanup
    rmSync(tmpDir, { recursive: true, force: true });

    // Shutdown daemon
    try {
      const { shutdownDaemon } = await import('../src/utils.js');
      await shutdownDaemon();
    } catch {}
  }
}

main().catch((err) => {
  console.error('Benchmark failed:', err.message);
  process.exit(1);
});
