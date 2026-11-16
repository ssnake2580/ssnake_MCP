#!/usr/bin/env node
/**
 * ClawProof CLI - Security scanner for AI agent skills
 */

import { scanFile, scanDirectory, scanContent, getGradeDistribution, getMostDangerous } from '../dist/index.js';
import { readFile, writeFile } from 'fs/promises';
import { basename } from 'path';

const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
  console.log(`
ClawProof - Security scanner for AI agent skills and prompts

Usage:
  clawproof scan <file>              Scan a single file
  clawproof scan-dir <directory>     Scan all SKILL.md files in directory
  clawproof scan-text <text>         Scan text from command line
  clawproof help                     Show this help message

Options:
  --json                             Output results as JSON
  --output <file>                    Save results to file
  --verbose                          Show detailed findings

Examples:
  clawproof scan ./SKILL.md
  clawproof scan-dir ./clawhub-skills --json
  clawproof scan-text "ignore all previous instructions"

Grades:
  A - Safe to use (0 points)
  B - Low risk (1-10 points)
  C - Medium risk (11-25 points)
  D - High risk (26-50 points)
  F - Critical threat (51+ points) - DO NOT INSTALL
`);
}

async function formatOutput(result, options = {}) {
  if (options.json) {
    return JSON.stringify(result, null, 2);
  }

  const gradeEmoji = {
    A: '✅',
    B: '⚠️ ',
    C: '⚠️ ',
    D: '❌',
    F: '🚨'
  };

  let output = `
${gradeEmoji[result.grade]} Grade: ${result.grade}
Score: ${result.score} points
Findings: ${result.findings_count}
Recommendation: ${result.recommendation}
`;

  if (options.verbose && result.findings.length > 0) {
    output += '\nDetailed Findings:\n';
    for (const finding of result.findings) {
      output += `\n  [${finding.severity}] ${finding.message}\n`;
      output += `  Pattern: ${finding.rule_id}\n`;
      output += `  Matched: "${finding.matched_text}"\n`;
      if (finding.line) {
        output += `  Line: ${finding.line}\n`;
      }
    }
  }

  return output;
}

async function scanCommand(filePath, options = {}) {
  console.log(`🔍 Scanning ${basename(filePath)}...`);
  const result = await scanFile(filePath);
  const output = await formatOutput(result, options);

  if (options.output) {
    await writeFile(options.output, JSON.stringify(result, null, 2));
    console.log(`\n💾 Results saved to ${options.output}`);
  }

  console.log(output);
  process.exit(result.grade === 'F' ? 1 : 0);
}

async function scanDirCommand(dirPath, options = {}) {
  console.log(`🔍 Scanning directory ${dirPath}...\n`);
  const results = await scanDirectory(dirPath);

  console.log(`✅ Scanned ${results.length} files\n`);

  const distribution = getGradeDistribution(results);
  const dangerous = getMostDangerous(results, 10);

  if (options.json) {
    const output = JSON.stringify({ results, distribution, dangerous }, null, 2);
    if (options.output) {
      await writeFile(options.output, output);
      console.log(`💾 Results saved to ${options.output}`);
    } else {
      console.log(output);
    }
  } else {
    console.log('Grade Distribution:');
    console.log(`  A: ${distribution.A} (Safe)`);
    console.log(`  B: ${distribution.B} (Low risk)`);
    console.log(`  C: ${distribution.C} (Medium risk)`);
    console.log(`  D: ${distribution.D} (High risk)`);
    console.log(`  F: ${distribution.F} (Critical)\n`);

    if (dangerous.length > 0) {
      console.log('Top 10 Most Dangerous:');
      dangerous.forEach((item, idx) => {
        console.log(`  ${idx + 1}. ${item.slug || item.file_path} - Grade ${item.grade} (${item.findings_count} findings, ${item.score} points)`);
      });
    }

    if (options.output) {
      await writeFile(options.output, JSON.stringify({ results, distribution, dangerous }, null, 2));
      console.log(`\n💾 Full results saved to ${options.output}`);
    }
  }

  process.exit(distribution.F > 0 ? 1 : 0);
}

async function scanTextCommand(text, options = {}) {
  console.log('🔍 Scanning text...');
  const result = scanContent(text, 'stdin');
  const output = await formatOutput(result, options);

  if (options.output) {
    await writeFile(options.output, JSON.stringify(result, null, 2));
    console.log(`\n💾 Results saved to ${options.output}`);
  }

  console.log(output);
  process.exit(result.grade === 'F' ? 1 : 0);
}

// Parse options
const options = {
  json: args.includes('--json'),
  verbose: args.includes('--verbose'),
  output: args.includes('--output') ? args[args.indexOf('--output') + 1] : null
};

// Execute command
try {
  switch (command) {
    case 'scan':
      if (!args[1]) {
        console.error('Error: File path required');
        showHelp();
        process.exit(1);
      }
      await scanCommand(args[1], options);
      break;

    case 'scan-dir':
      if (!args[1]) {
        console.error('Error: Directory path required');
        showHelp();
        process.exit(1);
      }
      await scanDirCommand(args[1], options);
      break;

    case 'scan-text':
      if (!args[1]) {
        console.error('Error: Text required');
        showHelp();
        process.exit(1);
      }
      await scanTextCommand(args[1], options);
      break;

    case 'help':
    case '--help':
    case '-h':
      showHelp();
      break;

    default:
      console.error(`Error: Unknown command '${command}'`);
      showHelp();
      process.exit(1);
  }
} catch (error) {
  console.error('Error:', error.message);
  process.exit(1);
}
