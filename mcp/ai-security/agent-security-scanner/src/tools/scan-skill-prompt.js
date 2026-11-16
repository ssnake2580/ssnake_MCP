/**
 * Prompt Security Scanner for ClawHub SKILL.md Files
 *
 * Scans prompt-based agent skills for:
 * - Prompt injection attacks
 * - Jailbreak attempts
 * - Data exfiltration patterns
 * - Privilege escalation
 * - Social engineering
 * - Misleading descriptions
 *
 * This scanner addresses the finding that 94% of ClawHub skills
 * are prompt templates, not executable code.
 */

import fs from 'fs/promises';
import path from 'path';

/**
 * Prompt injection detection patterns
 * Categorized by attack type and severity
 */
const PROMPT_PATTERNS = {
  // CRITICAL: Direct prompt injection attempts
  promptInjection: {
    severity: 'CRITICAL',
    patterns: [
      {
        name: 'Ignore Previous Instructions',
        regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|directives?|commands?|prompts?)/gi,
        description: 'Attempts to override system instructions',
        cwe: 'CWE-74'
      },
      {
        name: 'System Override',
        regex: /(override|disregard|forget|reset)\s+(system|instructions?|rules?|constraints?)/gi,
        description: 'Tries to bypass system constraints',
        cwe: 'CWE-74'
      },
      {
        name: 'Role Manipulation',
        regex: /(you\s+are\s+now|from\s+now\s+on.*you\s+are|act\s+as\s+if\s+you\s+are)\s+(a\s+)?(jailbroken|unrestricted|dan|sudo|admin|root)/gi,
        description: 'Attempts to change AI role to bypass restrictions',
        cwe: 'CWE-269'
      },
      {
        name: 'DAN (Do Anything Now) Jailbreak',
        regex: /(do\s+anything\s+now|DAN\s+mode|enable\s+developer\s+mode)/gi,
        description: 'Known jailbreak technique',
        cwe: 'CWE-269'
      }
    ]
  },

  // HIGH: Data exfiltration and privacy violations
  dataExfiltration: {
    severity: 'HIGH',
    patterns: [
      {
        name: 'Credential Harvesting',
        regex: /(send|transmit|provide|give\s+me)\s+(your|the|all)?\s*(api[\s_-]?keys?|passwords?|tokens?|credentials?|secrets?)/gi,
        description: 'Attempts to extract sensitive credentials',
        cwe: 'CWE-200'
      },
      {
        name: 'PII Exfiltration',
        regex: /(extract|collect|send|reveal)\s+(all\s+)?(user|personal)\s+(data|information|details|emails?|addresses?)/gi,
        description: 'Tries to access user personal information',
        cwe: 'CWE-359'
      },
      {
        name: 'Conversation History Access',
        regex: /(show|display|reveal|print)\s+(previous|all|entire)\s+(conversation|chat|history|messages?)/gi,
        description: 'Attempts to access conversation history',
        cwe: 'CWE-200'
      },
      {
        name: 'External Data Transmission',
        regex: /(send|post|upload|transmit)\s+(to|at)?\s*(https?:\/\/|www\.|pastebin|discord\.gg)/gi,
        description: 'Sends data to external servers',
        cwe: 'CWE-359'
      }
    ]
  },

  // HIGH: Jailbreak and constraint bypass
  jailbreak: {
    severity: 'HIGH',
    patterns: [
      {
        name: 'Pretend Mode',
        regex: /pretend\s+(you\s+are|to\s+be)\s+(unfiltered|unrestricted|without\s+limitations?)/gi,
        description: 'Jailbreak via roleplay',
        cwe: 'CWE-863'
      },
      {
        name: 'Hypothetical Scenario',
        regex: /in\s+a\s+hypothetical\s+(world|scenario|universe)\s+where\s+(you\s+)?(have\s+no|are\s+not\s+bound\s+by|ignore)/gi,
        description: 'Bypasses restrictions via hypotheticals',
        cwe: 'CWE-863'
      },
      {
        name: 'Developer Mode',
        regex: /(enable|activate|enter)\s+(developer|debug|god|admin)\s+mode/gi,
        description: 'Attempts to activate privileged mode',
        cwe: 'CWE-269'
      },
      {
        name: 'Emoji/Token Obfuscation',
        regex: /\[.*system.*\].*\[.*jailbreak.*\]|🔓|🔐.*bypass/gi,
        description: 'Uses symbols to obfuscate jailbreak',
        cwe: 'CWE-74'
      }
    ]
  },

  // MEDIUM: Social engineering and deception
  socialEngineering: {
    severity: 'MEDIUM',
    patterns: [
      {
        name: 'Authority Impersonation',
        regex: /(i\s+am|this\s+is)\s+(the\s+)?(admin|administrator|developer|ceo|owner|anthropic|openai)/gi,
        description: 'Impersonates authority figure',
        cwe: 'CWE-346'
      },
      {
        name: 'Urgency Manipulation',
        regex: /(urgent|emergency|critical|immediately).*(?:do\s+this|execute|run|bypass)/gi,
        description: 'Creates false urgency to bypass checks',
        cwe: 'CWE-346'
      },
      {
        name: 'Emotional Manipulation',
        regex: /(please\s+)?(help\s+me|i\s+need|my\s+(life|job|family)).*(?:ignore|bypass|override)/gi,
        description: 'Uses emotional appeals to manipulate',
        cwe: 'CWE-346'
      }
    ]
  },

  // MEDIUM: Code execution and command injection
  codeExecution: {
    severity: 'MEDIUM',
    patterns: [
      {
        name: 'Embedded Code Execution',
        regex: /(execute|run|eval)\s+(this\s+)?(code|command|script|function):\s*```/gi,
        description: 'Attempts to execute embedded code',
        cwe: 'CWE-94'
      },
      {
        name: 'Shell Command Injection',
        regex: /```(bash|sh|zsh|cmd|powershell)[\s\S]{0,50}(rm\s+-rf|del\s+\/|curl.*\||wget.*\||nc\s+-)/gi,
        description: 'Contains dangerous shell commands',
        cwe: 'CWE-78'
      },
      {
        name: 'SQL Injection in Prompts',
        regex: /(execute|run)\s+query:?\s*(['"`])?.*(?:DROP|DELETE|INSERT|UPDATE).*(?:users?|admin|password)/gi,
        description: 'SQL injection attempt in prompts',
        cwe: 'CWE-89'
      }
    ]
  },

  // LOW: Suspicious patterns and metadata issues
  suspiciousPatterns: {
    severity: 'LOW',
    patterns: [
      {
        name: 'Hidden Instructions',
        regex: /<!--[\s\S]*?(?:ignore|bypass|execute)[\s\S]*?-->/gi,
        description: 'Hidden instructions in HTML comments',
        cwe: 'CWE-506'
      },
      {
        name: 'Unicode Obfuscation',
        regex: /[\u200B-\u200D\uFEFF]/g,
        description: 'Zero-width characters for obfuscation',
        cwe: 'CWE-838'
      },
      {
        name: 'Excessive System References',
        regex: /(system|instruction|directive|constraint|limitation)/gi,
        description: 'Unusual focus on system internals',
        cwe: 'CWE-200'
      },
      {
        name: 'Base64 Encoded Prompts',
        regex: /(?:prompt|instruction|command).*[A-Za-z0-9+/]{40,}={0,2}/gi,
        description: 'Potentially obfuscated instructions',
        cwe: 'CWE-838'
      }
    ]
  }
};

/**
 * Metadata validation patterns
 * Checks for misleading or incomplete skill descriptions
 */
const METADATA_VALIDATORS = {
  descriptionQuality: {
    minLength: 20,
    maxLength: 500,
    requiresPurpose: true
  },
  authorValidation: {
    requiresAuthor: true,
    blockedAuthors: ['test', 'admin', 'root', 'system']
  },
  versionValidation: {
    requiresVersion: false,
    semanticVersion: /^\d+\.\d+\.\d+$/
  }
};

/**
 * Scan a SKILL.md file for prompt injection vulnerabilities
 */
export async function scanSkillPrompt(skillPath, options = {}) {
  const verbosity = options.verbosity || 'compact';
  const results = {
    skillPath,
    findings: [],
    metadata: {},
    score: 100,
    grade: 'A',
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
  };

  try {
    // Read SKILL.md file
    const content = await fs.readFile(skillPath, 'utf-8');

    // Parse frontmatter metadata
    results.metadata = parseSkillMetadata(content);

    // Scan for prompt injection patterns
    for (const [category, config] of Object.entries(PROMPT_PATTERNS)) {
      for (const pattern of config.patterns) {
        const matches = findMatches(content, pattern.regex);

        if (matches.length > 0) {
          const finding = {
            category,
            severity: config.severity,
            name: pattern.name,
            description: pattern.description,
            cwe: pattern.cwe,
            matches: matches.map(m => ({
              line: m.line,
              column: m.column,
              snippet: m.snippet
            })),
            count: matches.length
          };

          results.findings.push(finding);
          results.summary[config.severity.toLowerCase()]++;

          // Deduct points based on severity
          const deduction = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5
          }[config.severity] || 5;

          results.score -= deduction * matches.length;
        }
      }
    }

    // Validate metadata
    const metadataIssues = validateMetadata(results.metadata);
    results.findings.push(...metadataIssues);

    // Calculate final grade
    results.score = Math.max(0, results.score);
    results.grade = calculateGrade(results.score);

    // Format output based on verbosity
    return formatOutput(results, verbosity);

  } catch (error) {
    return {
      error: error.message,
      skillPath,
      success: false
    };
  }
}

/**
 * Parse SKILL.md frontmatter metadata
 */
function parseSkillMetadata(content) {
  const metadata = {
    name: null,
    description: null,
    author: null,
    version: null,
    tags: []
  };

  // Extract YAML frontmatter
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (frontmatterMatch) {
    const yaml = frontmatterMatch[1];

    // Simple YAML parsing (for basic fields)
    metadata.name = yaml.match(/name:\s*(.+)/)?.[1]?.trim();
    metadata.description = yaml.match(/description:\s*(.+)/)?.[1]?.trim();
    metadata.author = yaml.match(/author:\s*(.+)/)?.[1]?.trim();
    metadata.version = yaml.match(/version:\s*(.+)/)?.[1]?.trim();

    const tagsMatch = yaml.match(/tags:\s*\[(.*?)\]/);
    if (tagsMatch) {
      metadata.tags = tagsMatch[1].split(',').map(t => t.trim().replace(/['"]/g, ''));
    }
  }

  // Fallback: extract from first heading
  if (!metadata.name) {
    const headingMatch = content.match(/^#\s+(.+)$/m);
    if (headingMatch) metadata.name = headingMatch[1];
  }

  return metadata;
}

/**
 * Find all matches of a pattern in content with line/column info
 */
function findMatches(content, regex) {
  const matches = [];
  const lines = content.split('\n');

  lines.forEach((line, lineIndex) => {
    let match;
    const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');

    while ((match = globalRegex.exec(line)) !== null) {
      matches.push({
        line: lineIndex + 1,
        column: match.index,
        snippet: line.substring(Math.max(0, match.index - 20), match.index + match[0].length + 20),
        matchedText: match[0]
      });
    }
  });

  return matches;
}

/**
 * Validate skill metadata
 */
function validateMetadata(metadata) {
  const issues = [];

  // Description validation
  if (!metadata.description) {
    issues.push({
      category: 'metadata',
      severity: 'MEDIUM',
      name: 'Missing Description',
      description: 'Skill lacks a description',
      cwe: 'CWE-1007'
    });
  } else if (metadata.description.length < METADATA_VALIDATORS.descriptionQuality.minLength) {
    issues.push({
      category: 'metadata',
      severity: 'LOW',
      name: 'Insufficient Description',
      description: `Description too short (${metadata.description.length} chars, min ${METADATA_VALIDATORS.descriptionQuality.minLength})`,
      cwe: 'CWE-1007'
    });
  }

  // Author validation
  if (!metadata.author) {
    issues.push({
      category: 'metadata',
      severity: 'LOW',
      name: 'Missing Author',
      description: 'Skill lacks author information',
      cwe: 'CWE-1007'
    });
  } else if (METADATA_VALIDATORS.authorValidation.blockedAuthors.includes(metadata.author.toLowerCase())) {
    issues.push({
      category: 'metadata',
      severity: 'MEDIUM',
      name: 'Suspicious Author Name',
      description: `Author name "${metadata.author}" is suspicious`,
      cwe: 'CWE-346'
    });
  }

  return issues;
}

/**
 * Calculate letter grade from score
 */
function calculateGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

/**
 * Format output based on verbosity level
 */
function formatOutput(results, verbosity) {
  if (verbosity === 'minimal') {
    return {
      grade: results.grade,
      score: results.score,
      critical: results.summary.critical,
      high: results.summary.high
    };
  }

  if (verbosity === 'compact') {
    return {
      skillPath: results.skillPath,
      grade: results.grade,
      score: results.score,
      summary: results.summary,
      topIssues: results.findings
        .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
        .slice(0, 5)
        .map(f => ({
          severity: f.severity,
          name: f.name,
          description: f.description,
          count: f.count || 1
        }))
    };
  }

  // Full verbosity
  return results;
}

/**
 * Scan all SKILL.md files in a directory
 */
export async function scanSkillDirectory(dirPath, options = {}) {
  const results = {
    scanned: 0,
    findings: [],
    summary: {
      gradeA: 0,
      gradeB: 0,
      gradeC: 0,
      gradeD: 0,
      gradeF: 0,
      totalCritical: 0,
      totalHigh: 0,
      totalMedium: 0,
      totalLow: 0
    }
  };

  try {
    const skills = await findSkillFiles(dirPath);

    for (const skillPath of skills) {
      const scanResult = await scanSkillPrompt(skillPath, options);

      if (scanResult.grade) {
        results.scanned++;
        results.summary[`grade${scanResult.grade}`]++;
        results.summary.totalCritical += scanResult.summary?.critical || 0;
        results.summary.totalHigh += scanResult.summary?.high || 0;
        results.summary.totalMedium += scanResult.summary?.medium || 0;
        results.summary.totalLow += scanResult.summary?.low || 0;

        results.findings.push({
          skill: path.basename(path.dirname(skillPath)),
          ...scanResult
        });
      }
    }

    return results;

  } catch (error) {
    return {
      error: error.message,
      success: false
    };
  }
}

/**
 * Find all SKILL.md files recursively
 */
async function findSkillFiles(dirPath) {
  const skillFiles = [];

  async function traverse(currentPath) {
    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        await traverse(fullPath);
      } else if (entry.name === 'SKILL.md' || entry.name === 'skill.md') {
        skillFiles.push(fullPath);
      }
    }
  }

  await traverse(dirPath);
  return skillFiles;
}

// CLI support
if (import.meta.url === `file://${process.argv[1]}`) {
  const skillPath = process.argv[2];
  const verbosity = process.argv[3] || 'compact';

  if (!skillPath) {
    console.error('Usage: node scan-skill-prompt.js <skill-path> [verbosity]');
    process.exit(1);
  }

  const stats = await fs.stat(skillPath);
  const results = stats.isDirectory()
    ? await scanSkillDirectory(skillPath, { verbosity })
    : await scanSkillPrompt(skillPath, { verbosity });

  console.log(JSON.stringify(results, null, 2));
}
