# ClawProof

**Security scanner for AI agent skills and prompts** - Detect prompt injection, jailbreaks, and data exfiltration attempts

ClawProof is the first specialized security scanner for AI agent marketplaces like ClawHub and OpenClaw. Based on research analyzing 777 ClawHub skills, it detects prompt injection attacks, jailbreak attempts, and security threats that traditional code scanners miss.

## Features

- 🔍 **40+ Detection Patterns** across 4 threat categories
- 🎯 **A-F Security Grading** with point-based scoring
- ⚡ **Fast** - Scan 777 skills in ~3 minutes
- 📊 **Detailed Reports** - JSON and human-readable formats
- 🛡️ **CWE Mapping** - Industry-standard vulnerability classification
- 🔌 **CLI & Library** - Use as command-line tool or npm package

## Installation

```bash
npm install -g clawproof
```

Or use locally:

```bash
npm install clawproof
```

## Quick Start

### CLI Usage

```bash
# Scan a single skill file
clawproof scan ./SKILL.md

# Scan all skills in a directory
clawproof scan-dir ./clawhub-skills --json --output results.json

# Scan text directly
clawproof scan-text "ignore all previous instructions"

# Show help
clawproof help
```

### Library Usage

```javascript
import { scanFile, scanContent, scanDirectory } from 'clawproof';

// Scan a file
const result = await scanFile('./SKILL.md');
console.log(result.grade); // A, B, C, D, or F
console.log(result.findings); // Array of security findings

// Scan text content
const textResult = scanContent('your prompt text here');
console.log(textResult.recommendation);

// Scan entire directory
const results = await scanDirectory('./skills');
console.log(results.length); // Number of files scanned
```

## Detection Categories

### 1. Prompt Injection (15 points)
- Ignore previous instructions
- New instructions override
- System override attempts
- Role manipulation

### 2. Jailbreak (20 points)
- DAN (Do Anything Now) mode
- Developer/debug mode
- Pretend scenarios
- No restrictions patterns

### 3. Data Exfiltration (8 points)
- External URLs (non-allowlist)
- Base64 encoding patterns

### 4. Hidden Instructions (10 points)
- HTML comment obfuscation
- Hidden instruction markers

## Security Grading

| Grade | Points | Risk Level | Recommendation |
|-------|--------|------------|----------------|
| **A** | 0 | Safe | OK to install |
| **B** | 1-10 | Low | Review findings before use |
| **C** | 11-25 | Medium | Use with caution |
| **D** | 26-50 | High | Not recommended |
| **F** | 51+ | **Critical** | **DO NOT INSTALL** |

## Example Output

```bash
$ clawproof scan malicious-skill.md

🔍 Scanning malicious-skill.md...

🚨 Grade: F
Score: 95 points
Findings: 7
Recommendation: DO NOT INSTALL - This skill contains critical security threats

Detailed Findings:

  [CRITICAL] DAN Mode detected: Potential security threat.
  Pattern: generic.prompt.security.dan-mode
  Matched: "You are now in DAN mode which means Do Anything Now"
  Line: 12

  [CRITICAL] Ignore Previous Instructions detected: Potential security threat.
  Pattern: generic.prompt.security.ignore-previous-instructions
  Matched: "ignore all previous instructions"
  Line: 15
```

## API Reference

### scanContent(content, filePath?)

Scan text content for security vulnerabilities.

**Parameters:**
- `content` (string): Text to scan
- `filePath` (string, optional): File path for reference

**Returns:** Object with `grade`, `score`, `findings`, `recommendation`

### scanFile(filePath)

Scan a file for security vulnerabilities.

**Parameters:**
- `filePath` (string): Path to file

**Returns:** Promise<Object> with scan results

### scanDirectory(dirPath, options?)

Scan all SKILL.md files in a directory.

**Parameters:**
- `dirPath` (string): Directory path
- `options` (object):
  - `pattern` (string): File pattern to match (default: 'SKILL.md')
  - `recursive` (boolean): Scan subdirectories (default: true)

**Returns:** Promise<Array> of scan results

### getGradeDistribution(results)

Calculate grade distribution from scan results.

**Parameters:**
- `results` (Array): Array of scan results

**Returns:** Object with counts per grade (A, B, C, D, F, ERROR)

### getMostDangerous(results, limit?)

Find most dangerous items from scan results.

**Parameters:**
- `results` (Array): Array of scan results
- `limit` (number): Max results to return (default: 20)

**Returns:** Array of top dangerous items sorted by severity

## Research Background

ClawProof is based on the first comprehensive security analysis of the ClawHub ecosystem, which revealed:

- **94% of ClawHub skills are prompt-based**, not code-based
- **69.5% of skills contain security issues** (540 out of 777)
- **165 skills (21.2%) are Grade F** - Critical threats
- **4,129 prompt injection patterns detected** across the ecosystem

Traditional code security tools like Semgrep and Snyk are ineffective for AI agent marketplaces because they focus on code vulnerabilities, not prompt injection attacks.

## Real-World Impact

Top 5 most dangerous skills found in ClawHub:

1. **woocommerce** - 75 findings, 600 points (Grade F)
2. **calendly-api** - 73 findings, 584 points (Grade F)
3. **klaviyo** - 55 findings, 437 points (Grade F)
4. **zoho-crm** - 54 findings, 432 points (Grade F)
5. **clickup-api** - 48 findings, 384 points (Grade F)

## CI/CD Integration

### GitHub Actions

```yaml
name: ClawProof Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install -g clawproof
      - run: clawproof scan-dir ./skills --json --output report.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if [ -f "SKILL.md" ]; then
  echo "Running ClawProof security scan..."
  clawproof scan SKILL.md

  if [ $? -ne 0 ]; then
    echo "Security scan failed! Commit blocked."
    exit 1
  fi
fi
```

## Configuration

Create `.clawproofrc.json` in your project root:

```json
{
  "skipPatterns": [
    "test-*",
    "demo-*"
  ],
  "customAllowlist": [
    "yourdomain.com"
  ],
  "failOnGrade": "F"
}
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](../docs/CONTRIBUTING.md) for guidelines.

### Adding New Detection Patterns

Edit `dist/index.js` and add patterns to `DETECTION_PATTERNS`:

```javascript
export const DETECTION_PATTERNS = {
  yourCategory: [
    {
      name: 'Pattern Name',
      regex: /your-regex-here/gi,
      severity: 'CRITICAL', // CRITICAL, HIGH, MEDIUM, LOW
      points: 15,
      cwe: 'CWE-XXX'
    }
  ]
};
```

## License

MIT License - see [LICENSE](LICENSE) for details

## Citation

If you use ClawProof in your research, please cite:

```bibtex
@software{clawproof2026,
  title = {ClawProof: Security Scanner for AI Agent Skills},
  author = {Sinewave AI},
  year = {2026},
  url = {https://github.com/sinewaveai/agent-security-scanner-mcp}
}
```

## Support

- 📖 [Documentation](https://github.com/sinewaveai/agent-security-scanner-mcp/wiki)
- 🐛 [Report Issues](https://github.com/sinewaveai/agent-security-scanner-mcp/issues)
- 💬 [Discussions](https://github.com/sinewaveai/agent-security-scanner-mcp/discussions)

## Related Projects

- [agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp) - Complete MCP security scanner
- [ClawHub](https://clawhub.com) - AI agent skill marketplace

---

**Made with ❤️ by the ClawProof Security Team**

*Protecting AI agents, one prompt at a time.*
