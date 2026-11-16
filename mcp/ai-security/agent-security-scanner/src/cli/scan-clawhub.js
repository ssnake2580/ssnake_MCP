#!/usr/bin/env node

/**
 * scan-clawhub-v2.js
 *
 * Batch scan all ClawHub skills - REVISED STRATEGY
 *
 * Strategy:
 * 1. Use ClawHub CLI to list all skills
 * 2. Install each skill to temp directory using `clawhub install`
 * 3. Scan SKILL.md files from installed skills
 * 4. Generate A-F grades and aggregate findings
 * 5. Output JSON report + stats
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execAsync = promisify(exec);

// Configuration
const SCAN_DIR = path.join(process.cwd(), 'clawhub-scan');
const SKILLS_DIR = path.join(SCAN_DIR, 'skills-installed');
const RESULTS_FILE = path.join(SCAN_DIR, 'results.json');
const REPORT_FILE = path.join(SCAN_DIR, 'report.json');

const CONCURRENT_DOWNLOADS = 5; // Conservative to avoid rate limiting
const CONCURRENT_SCANS = 10;

/**
 * Fetch all skills from ClawHub
 */
async function fetchAllSkills() {
  console.log('📥 Fetching all skills from ClawHub...');

  const allSkills = [];
  const seenSlugs = new Set();
  const sortOrders = ['newest', 'downloads', 'installsAllTime'];

  for (const sortOrder of sortOrders) {
    try {
      const { stdout } = await execAsync(
        `clawhub explore --limit 200 --sort ${sortOrder} --json 2>&1`
      );

      const jsonStr = stdout.split('\n').slice(1).join('\n');
      const data = JSON.parse(jsonStr);

      if (data.items && Array.isArray(data.items)) {
        for (const skill of data.items) {
          if (!seenSlugs.has(skill.slug)) {
            seenSlugs.add(skill.slug);
            allSkills.push(skill);
          }
        }
      }

      console.log(`  ✓ Fetched ${data.items.length} skills (sort: ${sortOrder})`);
    } catch (error) {
      console.error(`  ✗ Error fetching skills (sort: ${sortOrder}):`, error.message);
    }
  }

  console.log(`\n✅ Total unique skills found: ${allSkills.length}\n`);
  return allSkills;
}

/**
 * Install a skill using clawhub install
 */
async function installSkill(slug) {
  const skillDir = path.join(SKILLS_DIR, slug);
  const skillFile = path.join(skillDir, 'SKILL.md');

  // Check if already installed
  try {
    await fs.access(skillFile);
    return { slug, skillFile, cached: true };
  } catch {
    // Not cached
  }

  try {
    // Install skill using ClawHub CLI
    await execAsync(
      `clawhub install ${slug} --workdir "${SKILLS_DIR}" --no-input`,
      { timeout: 60000 }
    );

    // Check if SKILL.md exists
    try {
      await fs.access(skillFile);
      return { slug, skillFile, cached: false };
    } catch {
      return { slug, skillFile: null, error: 'SKILL.md not found after install' };
    }
  } catch (error) {
    return { slug, skillFile: null, error: error.message };
  }
}

/**
 * Scan a skill
 */
async function scanSkill(slug, skillFile) {
  if (!skillFile) {
    return {
      slug,
      grade: 'F',
      error: 'Skill file not available'
    };
  }

  try {
    const scannerPath = path.join(__dirname, '..', '..', 'index.js');
    const { stdout } = await execAsync(
      `node "${scannerPath}" scan-skill "${skillFile}" --verbosity compact`,
      { timeout: 120000 }
    );

    const result = JSON.parse(stdout);

    return {
      slug,
      grade: result.grade || 'F',
      findings: result.findings || [],
      findingsCount: result.findings_count || 0,
      recommendation: result.recommendation
    };
  } catch (error) {
    return {
      slug,
      grade: 'F',
      error: error.message,
      findings: []
    };
  }
}

/**
 * Batch install skills
 */
async function installSkillsBatch(skills) {
  console.log(`📦 Installing ${skills.length} skills...\n`);

  const results = [];
  let completed = 0;

  for (let i = 0; i < skills.length; i += CONCURRENT_DOWNLOADS) {
    const batch = skills.slice(i, i + CONCURRENT_DOWNLOADS);
    const promises = batch.map(skill => installSkill(skill.slug));
    const batchResults = await Promise.all(promises);

    results.push(...batchResults);
    completed += batch.length;

    const progress = ((completed / skills.length) * 100).toFixed(1);
    const cached = batchResults.filter(r => r.cached).length;
    const successful = batchResults.filter(r => r.skillFile !== null).length;

    console.log(`  [${progress}%] ${completed}/${skills.length} (${successful} ok, ${cached} cached)`);
  }

  const successful = results.filter(r => r.skillFile !== null).length;
  const failed = results.length - successful;

  console.log(`\n✅ Install complete: ${successful} successful, ${failed} failed\n`);
  return results;
}

/**
 * Batch scan skills
 */
async function scanSkillsBatch(installedSkills) {
  console.log(`🔍 Scanning ${installedSkills.length} skills...\n`);

  const results = [];
  let completed = 0;

  for (let i = 0; i < installedSkills.length; i += CONCURRENT_SCANS) {
    const batch = installedSkills.slice(i, i + CONCURRENT_SCANS);
    const promises = batch.map(({ slug, skillFile }) => scanSkill(slug, skillFile));
    const batchResults = await Promise.all(promises);

    results.push(...batchResults);
    completed += batch.length;

    const progress = ((completed / installedSkills.length) * 100).toFixed(1);
    console.log(`  [${progress}%] Scanned ${completed}/${installedSkills.length}`);
  }

  console.log(`\n✅ Scan complete!\n`);
  return results;
}

/**
 * Generate report
 */
function generateReport(scanResults) {
  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  const totalFindings = { critical: 0, warning: 0, info: 0 };
  const topIssues = {};

  for (const result of scanResults) {
    gradeDistribution[result.grade] = (gradeDistribution[result.grade] || 0) + 1;

    if (result.findings && Array.isArray(result.findings)) {
      for (const finding of result.findings) {
        const severity = finding.severity?.toLowerCase() || 'info';
        if (severity === 'critical' || severity === 'error') {
          totalFindings.critical++;
        } else if (severity === 'warning') {
          totalFindings.warning++;
        } else {
          totalFindings.info++;
        }

        const ruleId = finding.rule_id || finding.ruleId || 'unknown';
        topIssues[ruleId] = (topIssues[ruleId] || 0) + 1;
      }
    }
  }

  const topIssuesSorted = Object.entries(topIssues)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([rule, count]) => ({ rule, count }));

  const totalSkills = scanResults.length;
  const vulnerableSkills = scanResults.filter(r => r.findingsCount > 0).length;

  return {
    summary: {
      totalSkills,
      vulnerableSkills,
      vulnerabilityRate: ((vulnerableSkills / totalSkills) * 100).toFixed(1) + '%',
      gradeDistribution,
      totalFindings
    },
    topIssues: topIssuesSorted,
    scannedAt: new Date().toISOString(),
    scannerVersion: '3.10.3'
  };
}

/**
 * Main
 */
async function main() {
  console.log('🛡️  ClawHub Security Scanner v2\n');
  console.log('═'.repeat(60) + '\n');

  await fs.mkdir(SKILLS_DIR, { recursive: true });

  const skills = await fetchAllSkills();
  if (skills.length === 0) {
    console.error('❌ No skills found');
    process.exit(1);
  }

  const installedSkills = await installSkillsBatch(skills);
  const validSkills = installedSkills.filter(s => s.skillFile !== null);

  if (validSkills.length === 0) {
    console.error('❌ No skills installed successfully');
    process.exit(1);
  }

  const scanResults = await scanSkillsBatch(validSkills);
  const report = generateReport(scanResults);

  await fs.writeFile(RESULTS_FILE, JSON.stringify(scanResults, null, 2));
  await fs.writeFile(REPORT_FILE, JSON.stringify(report, null, 2));

  console.log('📊 Results Summary\n');
  console.log('─'.repeat(60));
  console.log(`Total skills scanned: ${report.summary.totalSkills}`);
  console.log(`Vulnerable skills: ${report.summary.vulnerableSkills} (${report.summary.vulnerabilityRate})`);
  console.log(`\nGrade Distribution:`);
  console.log(`  A: ${report.summary.gradeDistribution.A}`);
  console.log(`  B: ${report.summary.gradeDistribution.B}`);
  console.log(`  C: ${report.summary.gradeDistribution.C}`);
  console.log(`  D: ${report.summary.gradeDistribution.D}`);
  console.log(`  F: ${report.summary.gradeDistribution.F}`);
  console.log(`\nTotal Findings:`);
  console.log(`  Critical: ${report.summary.totalFindings.critical}`);
  console.log(`  Warning: ${report.summary.totalFindings.warning}`);
  console.log(`  Info: ${report.summary.totalFindings.info}`);
  console.log(`\nTop 10 Issues:`);
  report.topIssues.slice(0, 10).forEach((issue, i) => {
    console.log(`  ${i + 1}. ${issue.rule} (${issue.count} occurrences)`);
  });
  console.log('\n' + '─'.repeat(60));
  console.log(`\n✅ Results saved to:`);
  console.log(`   ${RESULTS_FILE}`);
  console.log(`   ${REPORT_FILE}\n`);
}

main().catch(error => {
  console.error('\n❌ Fatal error:', error);
  process.exit(1);
});
