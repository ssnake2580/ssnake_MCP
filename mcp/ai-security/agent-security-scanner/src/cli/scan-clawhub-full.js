#!/usr/bin/env node

/**
 * scan-clawhub-full.js
 *
 * FULL ClawHub Implementation Scanning
 *
 * Strategy:
 * 1. Download SKILL.md files from all ClawHub skills (metadata)
 * 2. For each skill, extract GitHub repo URL or npm package name
 * 3. Download actual implementation code (GitHub clone OR npm pack)
 * 4. Scan implementation using full AST + taint + regex engine
 * 5. Generate comprehensive security report
 *
 * This matches Snyk's ToxicSkills methodology but adds:
 * - AST + taint analysis (vs their LLM-powered scanning)
 * - Package hallucination detection
 * - Cross-file taint tracking
 * - Interprocedural dataflow analysis
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';
import https from 'https';
import { fileURLToPath } from 'url';
import { cloneAndExtract, parseGitHubUrl } from '../utils/github-clone.js';
import { downloadAndExtract, getPackageMetadata } from '../utils/npm-download.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execAsync = promisify(exec);

// Configuration
const SCAN_DIR = path.join(process.cwd(), 'clawhub-scan-full');
const SKILLS_METADATA_DIR = path.join(SCAN_DIR, 'skills-metadata');
const SOURCE_CODE_DIR = path.join(SCAN_DIR, 'source-code');
const RESULTS_FILE = path.join(SCAN_DIR, 'results.json');
const REPORT_FILE = path.join(SCAN_DIR, 'report.json');

const CONCURRENT_DOWNLOADS = 5;
const CONCURRENT_SCANS = 3;
const SKILL_TIMEOUT_MS = 180_000; // 3 minutes per skill

/**
 * Fetch from URL
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
 * Fetch all skills from ClawHub registry
 */
async function fetchAllSkills() {
  console.log('\n📥 Fetching all skills from ClawHub...\n');

  const allSkills = new Map();
  const sorts = ['newest', 'downloads', 'installsAllTime'];

  for (const sort of sorts) {
    try {
      console.log(`  Fetching ${sort}...`);

      //Add delay between requests to avoid rate limits
      if (allSkills.size > 0) {
        await new Promise(resolve => setTimeout(resolve, 3000));
      }

      const { stdout } = await execAsync(
        `clawhub explore --limit 200 --sort ${sort} --json 2>&1`,
        { timeout: 60000 }
      );

      // Parse JSON - skip first line which is progress text
      const lines = stdout.trim().split('\n');
      const jsonStartIndex = lines.findIndex(line => line.trim().startsWith('{'));

      if (jsonStartIndex === -1) {
        console.log(`  ✗ No JSON output for ${sort}`);
        continue;
      }

      // Join all lines from the JSON start onwards
      const jsonText = lines.slice(jsonStartIndex).join('\n');
      const data = JSON.parse(jsonText);
      const skills = data.items || [];

      for (const skill of skills) {
        const key = `${skill.author_username || skill.author}/${skill.skill_slug || skill.slug}`;
        if (!allSkills.has(key)) {
          allSkills.set(key, {
            skill_slug: skill.slug,
            author_username: skill.author_username,
          });
        }
      }

      console.log(`  ✓ Fetched ${skills.length} skills (sort: ${sort})`);
    } catch (error) {
      console.log(`  ✗ Error fetching skills (sort: ${sort}): ${error.message}`);
    }
  }

  const skillsArray = Array.from(allSkills.values());
  console.log(`\n✅ Total unique skills found: ${skillsArray.length}\n`);

  return skillsArray;
}

/**
 * Download SKILL.md files using clawhub inspect
 */
async function downloadSkillMetadata(skills) {
  console.log(`📦 Downloading ${skills.length} skill SKILL.md files...\n`);

  await fs.mkdir(SKILLS_METADATA_DIR, { recursive: true });

  const results = [];
  const chunks = [];

  for (let i = 0; i < skills.length; i += CONCURRENT_DOWNLOADS) {
    chunks.push(skills.slice(i, i + CONCURRENT_DOWNLOADS));
  }

  for (const chunk of chunks) {
    const promises = chunk.map(async (skill) => {
      const skillDir = path.join(SKILLS_METADATA_DIR, skill.skill_slug);
      await fs.mkdir(skillDir, { recursive: true });

      const skillFilePath = path.join(skillDir, 'SKILL.md');

      try {
        // Step 1: Get metadata (owner info) using --json
        const { stdout: metadataOut } = await execAsync(
          `clawhub inspect ${skill.skill_slug} --json 2>&1`,
          { timeout: 30000 }
        );

        // Parse JSON - skip progress line
        const lines = metadataOut.trim().split('\n');
        const jsonStartIndex = lines.findIndex(line => line.trim().startsWith('{'));

        if (jsonStartIndex === -1) {
          return { slug: skill.skill_slug, success: false, error: 'No JSON in inspect output' };
        }

        const jsonText = lines.slice(jsonStartIndex).join('\n');
        const metadata = JSON.parse(jsonText);

        // Extract author from metadata
        const author = metadata.owner?.handle || metadata.owner?.displayName || 'unknown';

        // Step 2: Get SKILL.md file content using --file
        const { stdout: fileOut } = await execAsync(
          `clawhub inspect ${skill.skill_slug} --file SKILL.md 2>&1`,
          { timeout: 30000 }
        );

        // Skip the "- Fetching skill" progress line
        const fileLines = fileOut.trim().split('\n');
        const contentStartIndex = fileLines.findIndex(line => line.startsWith('---'));

        if (contentStartIndex === -1) {
          return { slug: skill.skill_slug, success: false, error: 'No SKILL.md content found' };
        }

        const skillMdContent = fileLines.slice(contentStartIndex).join('\n');

        if (!skillMdContent) {
          return { slug: skill.skill_slug, success: false, error: 'Empty SKILL.md file' };
        }

        await fs.writeFile(skillFilePath, skillMdContent, 'utf-8');

        return {
          slug: skill.skill_slug,
          author,
          skillMdPath: skillFilePath,
          skillMdContent,
          success: true,
        };
      } catch (error) {
        return { slug: skill.skill_slug, success: false, error: error.message };
      }
    });

    const chunkResults = await Promise.all(promises);
    results.push(...chunkResults);

    const completed = results.length;
    const successful = results.filter(r => r.success).length;
    console.log(`  [${((completed / skills.length) * 100).toFixed(1)}%] ${completed}/${skills.length} (${successful} ok)`);
  }

  const successful = results.filter(r => r.success);
  console.log(`\n✅ Download complete: ${successful.length} successful, ${results.length - successful.length} failed\n`);

  return successful;
}

/**
 * Extract GitHub or npm info from SKILL.md
 */
function extractSourceInfo(skillMdContent) {
  // Extract frontmatter
  const frontmatterMatch = skillMdContent.match(/^---\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) return null;

  const frontmatter = frontmatterMatch[1];
  const lines = frontmatter.split('\n');

  const info = {
    homepage: null,
    npm: null,
    github: null,
  };

  for (const line of lines) {
    if (line.startsWith('homepage:')) {
      info.homepage = line.replace('homepage:', '').trim();
    }
    if (line.startsWith('npm:')) {
      info.npm = line.replace('npm:', '').trim();
    }
  }

  // Parse GitHub URL from homepage
  if (info.homepage && info.homepage.includes('github.com')) {
    const parsed = parseGitHubUrl(info.homepage);
    if (parsed) {
      info.github = `https://github.com/${parsed.owner}/${parsed.repo}`;
    }
  }

  // Extract npm package name from URL
  if (info.npm && info.npm.includes('npmjs.com/package/')) {
    const match = info.npm.match(/npmjs\.com\/package\/([^\/\?#]+)/);
    if (match) {
      info.npmPackage = match[1];
    }
  }

  return info;
}

/**
 * Download source code for a skill (GitHub OR npm)
 */
async function downloadSkillSource(skill) {
  const sourceInfo = extractSourceInfo(skill.skillMdContent);

  if (!sourceInfo) {
    return {
      slug: skill.slug,
      success: false,
      error: 'No source info found in SKILL.md',
    };
  }

  const skillSourceDir = path.join(SOURCE_CODE_DIR, skill.slug);
  await fs.mkdir(skillSourceDir, { recursive: true });

  // Try GitHub first (safer)
  if (sourceInfo.github) {
    try {
      const result = await cloneAndExtract(sourceInfo.github, skillSourceDir);

      if (result.success) {
        return {
          slug: skill.slug,
          author: skill.author,
          success: true,
          method: 'github',
          sourcePath: result.sourcePath,
          size: result.repoSize,
        };
      }
    } catch (error) {
      console.log(`    GitHub clone failed for ${skill.slug}: ${error.message}`);
    }
  }

  // Fallback to npm
  if (sourceInfo.npmPackage) {
    try {
      const result = await downloadAndExtract(sourceInfo.npmPackage, skillSourceDir);

      if (result.success) {
        return {
          slug: skill.slug,
          author: skill.author,
          success: true,
          method: 'npm',
          sourcePath: result.sourcePath,
          size: result.packageSize,
        };
      }
    } catch (error) {
      console.log(`    npm download failed for ${skill.slug}: ${error.message}`);
    }
  }

  return {
    slug: skill.slug,
    success: false,
    error: 'Neither GitHub nor npm source available',
  };
}

/**
 * Download all skill source code
 */
async function downloadAllSources(skillsWithMetadata) {
  console.log(`\n🔍 Downloading source code for ${skillsWithMetadata.length} skills...\n`);

  const results = [];
  const chunks = [];

  for (let i = 0; i < skillsWithMetadata.length; i += CONCURRENT_DOWNLOADS) {
    chunks.push(skillsWithMetadata.slice(i, i + CONCURRENT_DOWNLOADS));
  }

  for (const chunk of chunks) {
    const promises = chunk.map(skill => downloadSkillSource(skill));
    const chunkResults = await Promise.all(promises);
    results.push(...chunkResults);

    const completed = results.length;
    const successful = results.filter(r => r.success).length;
    const github = results.filter(r => r.method === 'github').length;
    const npm = results.filter(r => r.method === 'npm').length;

    console.log(`  [${((completed / skillsWithMetadata.length) * 100).toFixed(1)}%] ${completed}/${skillsWithMetadata.length} (${successful} ok: ${github} github, ${npm} npm)`);
  }

  const successful = results.filter(r => r.success);
  const github = results.filter(r => r.method === 'github').length;
  const npm = results.filter(r => r.method === 'npm').length;

  console.log(`\n✅ Source download complete: ${successful.length}/${results.length} successful`);
  console.log(`   📦 GitHub: ${github}, npm: ${npm}\n`);

  return successful;
}

/**
 * Scan a single skill's source code
 */
async function scanSkillSource(skill) {
  try {
    const scanCmd = `node ${path.join(__dirname, '..', '..', 'index.js')} scan-project "${skill.sourcePath}" --format json`;

    const { stdout } = await execAsync(scanCmd, {
      timeout: SKILL_TIMEOUT_MS,
      maxBuffer: 10 * 1024 * 1024,
    });

    const scanResult = JSON.parse(stdout);

    return {
      slug: skill.slug,
      author: skill.author,
      method: skill.method,
      grade: scanResult.grade || 'F',
      findings: scanResult.findings || [],
      findingsCount: scanResult.findingsCount || 0,
      criticalCount: scanResult.criticalFindings || 0,
      recommendation: scanResult.recommendation || '',
      success: true,
    };
  } catch (error) {
    return {
      slug: skill.slug,
      success: false,
      grade: 'F',
      error: error.message,
    };
  }
}

/**
 * Scan all skill sources
 */
async function scanAllSources(skillsWithSources) {
  console.log(`\n🔍 Scanning ${skillsWithSources.length} skills...\n`);

  const results = [];
  const chunks = [];

  for (let i = 0; i < skillsWithSources.length; i += CONCURRENT_SCANS) {
    chunks.push(skillsWithSources.slice(i, i + CONCURRENT_SCANS));
  }

  for (const chunk of chunks) {
    const promises = chunk.map(skill => scanSkillSource(skill));
    const chunkResults = await Promise.all(promises);
    results.push(...chunkResults);

    console.log(`  [${((results.length / skillsWithSources.length) * 100).toFixed(1)}%] Scanned ${results.length}/${skillsWithSources.length}`);
  }

  console.log(`\n✅ Scan complete!\n`);

  return results;
}

/**
 * Generate report
 */
function generateReport(scanResults) {
  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  const totalFindings = { critical: 0, high: 0, medium: 0, low: 0 };
  const issuesByRule = new Map();

  for (const result of scanResults) {
    gradeDistribution[result.grade] = (gradeDistribution[result.grade] || 0) + 1;

    for (const finding of (result.findings || [])) {
      const severity = finding.severity || 'MEDIUM';
      totalFindings[severity.toLowerCase()] = (totalFindings[severity.toLowerCase()] || 0) + 1;

      const ruleId = finding.rule || 'unknown';
      issuesByRule.set(ruleId, (issuesByRule.get(ruleId) || 0) + 1);
    }
  }

  const vulnerableSkills = scanResults.filter(r => r.findingsCount > 0).length;
  const topIssues = Array.from(issuesByRule.entries())
    .map(([rule, count]) => ({ rule, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    summary: {
      totalSkills: scanResults.length,
      vulnerableSkills,
      vulnerabilityRate: ((vulnerableSkills / scanResults.length) * 100).toFixed(1) + '%',
      gradeDistribution,
      totalFindings,
    },
    topIssues,
    scanResults,
  };
}

/**
 * Main execution
 */
async function main() {
  console.log('🛡️  ClawHub Full Implementation Scanner\n');
  console.log('════════════════════════════════════════════════════════════');
  console.log('SAFE MODE: GitHub clone + npm pack (NO code execution)');
  console.log('DEEP ANALYSIS: AST + taint + regex + hallucination detection');
  console.log('════════════════════════════════════════════════════════════\n');

  try {
    // Step 1: Fetch skill list
    const allSkills = await fetchAllSkills();

    // Step 2: Download SKILL.md files
    const skillsWithMetadata = await downloadSkillMetadata(allSkills);

    // Step 3: Download source code (GitHub + npm)
    const skillsWithSources = await downloadAllSources(skillsWithMetadata);

    // Step 4: Scan source code
    const scanResults = await scanAllSources(skillsWithSources);

    // Step 5: Generate report
    const report = generateReport(scanResults);

    // Save results
    await fs.mkdir(SCAN_DIR, { recursive: true });
    await fs.writeFile(RESULTS_FILE, JSON.stringify(scanResults, null, 2));
    await fs.writeFile(REPORT_FILE, JSON.stringify(report, null, 2));

    // Print summary
    console.log('\n📊 Results Summary\n');
    console.log('────────────────────────────────────────────────────────────');
    console.log(`Total skills scanned: ${report.summary.totalSkills}`);
    console.log(`Vulnerable skills: ${report.summary.vulnerableSkills} (${report.summary.vulnerabilityRate})`);
    console.log('');
    console.log('Grade Distribution:');
    for (const [grade, count] of Object.entries(report.summary.gradeDistribution)) {
      console.log(`  ${grade}: ${count}`);
    }
    console.log('');
    console.log('Total Findings:');
    for (const [severity, count] of Object.entries(report.summary.totalFindings)) {
      console.log(`  ${severity}: ${count}`);
    }
    console.log('');
    console.log('Top 10 Issues:');
    for (const issue of report.topIssues) {
      console.log(`  ${issue.rule}: ${issue.count}`);
    }
    console.log('────────────────────────────────────────────────────────────\n');
    console.log(`✅ Results saved to:`);
    console.log(`   ${RESULTS_FILE}`);
    console.log(`   ${REPORT_FILE}\n`);

  } catch (error) {
    console.error(`\n❌ Fatal error: ${error.message}\n`);
    process.exit(1);
  }
}

main();
