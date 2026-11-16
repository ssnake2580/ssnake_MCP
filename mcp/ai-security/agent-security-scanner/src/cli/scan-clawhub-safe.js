#!/usr/bin/env node

/**
 * scan-clawhub-safe.js
 *
 * SAFE ClawHub Scanner - No Code Execution
 *
 * Strategy:
 * 1. Fetch skill list from ClawHub CLI (safe - just metadata)
 * 2. For each skill, scrape SKILL.md from web page (read-only)
 * 3. Write SKILL.md to temp files
 * 4. Scan with our engine
 * 5. Clean up temp files
 *
 * SECURITY: No npm install, no code execution, read-only operations
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import https from 'https';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execAsync = promisify(exec);

// Configuration
const SCAN_DIR = path.join(process.cwd(), 'clawhub-scan-safe');
const SKILLS_DIR = path.join(SCAN_DIR, 'skills');
const RESULTS_FILE = path.join(SCAN_DIR, 'results.json');
const REPORT_FILE = path.join(SCAN_DIR, 'report.json');

const CONCURRENT_DOWNLOADS = 10;
const CONCURRENT_SCANS = 10;

/**
 * Fetch from URL (promisified)
 */
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    }).on('error', reject);
  });
}

/**
 * Fetch all skills from ClawHub (SAFE - just metadata)
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
 * Download SKILL.md content from web (SAFE - read-only HTTP GET)
 */
async function downloadSkillContent(slug, owner) {
  const skillDir = path.join(SKILLS_DIR, slug);
  const skillFile = path.join(skillDir, 'SKILL.md');

  // Check if already downloaded
  try {
    await fs.access(skillFile);
    const content = await fs.readFile(skillFile, 'utf8');
    return { slug, skillFile, content, cached: true };
  } catch {
    // Not cached
  }

  try {
    // Try to fetch from ClawHub web page
    // The skill page URL format is: https://clawhub.ai/{owner}/{slug}
    const skillUrl = `https://clawhub.ai/${owner}/${slug}`;

    const { statusCode, body } = await fetchUrl(skillUrl);

    if (statusCode !== 200) {
      return { slug, skillFile: null, error: `HTTP ${statusCode}` };
    }

    // Extract SKILL.md content from HTML
    // ClawHub likely embeds the markdown in the page
    // We'll look for markdown content in the HTML

    // Simple extraction: look for markdown code blocks or pre tags
    // This is a heuristic - adjust based on actual ClawHub HTML structure
    let skillContent = '';

    // Try to extract markdown from HTML (basic approach)
    const markdownMatch = body.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
    if (markdownMatch) {
      skillContent = markdownMatch[1]
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");
    }

    // If no content found, try another pattern
    if (!skillContent) {
      // Look for the skill description/summary as fallback
      const descMatch = body.match(/<meta\s+name="description"\s+content="([^"]+)"/i);
      if (descMatch) {
        skillContent = `# ${slug}\n\n${descMatch[1]}`;
      }
    }

    if (!skillContent || skillContent.length < 50) {
      return { slug, skillFile: null, error: 'Could not extract SKILL.md from web page' };
    }

    // Create directory and write file
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(skillFile, skillContent, 'utf8');

    return { slug, skillFile, content: skillContent, cached: false };
  } catch (error) {
    return { slug, skillFile: null, error: error.message };
  }
}

/**
 * Alternative: Use our own skill file as template
 * Download from GitHub if skill author published it there
 */
async function downloadFromGitHub(slug, owner) {
  try {
    // Common patterns: username/skillname, skillname-skill, etc.
    const possibleRepos = [
      `${slug}`,
      `${slug}-skill`,
      `openclaw-${slug}`,
      `${slug.replace(/-/g, '_')}`
    ];

    for (const repo of possibleRepos) {
      const url = `https://raw.githubusercontent.com/${owner}/${repo}/main/SKILL.md`;
      const { statusCode, body } = await fetchUrl(url);

      if (statusCode === 200 && body.length > 100) {
        return body;
      }
    }

    return null;
  } catch {
    return null;
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
 * Batch download
 */
async function downloadSkillsBatch(skills) {
  console.log(`📦 Downloading ${skills.length} skill SKILL.md files (read-only, safe)...\n`);

  const results = [];
  let completed = 0;

  for (let i = 0; i < skills.length; i += CONCURRENT_DOWNLOADS) {
    const batch = skills.slice(i, i + CONCURRENT_DOWNLOADS);
    const promises = batch.map(skill =>
      downloadSkillContent(skill.slug, skill.owner?.handle || 'unknown')
    );
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

  console.log(`\n✅ Download complete: ${successful} successful, ${failed} failed\n`);
  return results;
}

/**
 * Batch scan
 */
async function scanSkillsBatch(downloadedSkills) {
  console.log(`🔍 Scanning ${downloadedSkills.length} skills...\n`);

  const results = [];
  let completed = 0;

  for (let i = 0; i < downloadedSkills.length; i += CONCURRENT_SCANS) {
    const batch = downloadedSkills.slice(i, i + CONCURRENT_SCANS);
    const promises = batch.map(({ slug, skillFile }) => scanSkill(slug, skillFile));
    const batchResults = await Promise.all(promises);

    results.push(...batchResults);
    completed += batch.length;

    const progress = ((completed / downloadedSkills.length) * 100).toFixed(1);
    console.log(`  [${progress}%] Scanned ${completed}/${downloadedSkills.length}`);
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
    scannerVersion: '3.10.3',
    scanMethod: 'safe-web-scraping'
  };
}

/**
 * Main
 */
async function main() {
  console.log('🛡️  ClawHub Security Scanner (SAFE MODE)\n');
  console.log('═'.repeat(60));
  console.log('SECURITY: Read-only, no code execution, web scraping only\n');
  console.log('═'.repeat(60) + '\n');

  await fs.mkdir(SKILLS_DIR, { recursive: true });

  const skills = await fetchAllSkills();
  if (skills.length === 0) {
    console.error('❌ No skills found');
    process.exit(1);
  }

  const downloadedSkills = await downloadSkillsBatch(skills);
  const validSkills = downloadedSkills.filter(s => s.skillFile !== null);

  if (validSkills.length === 0) {
    console.error('❌ No skills downloaded successfully');
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
