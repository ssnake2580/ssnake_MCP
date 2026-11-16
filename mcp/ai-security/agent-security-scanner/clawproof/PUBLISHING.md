# Publishing ClawProof to npm

## Package Overview

**Name:** `clawproof`
**Version:** 1.0.0
**Description:** Security scanner for AI agent skills and prompts - detects prompt injection, jailbreaks, and data exfiltration

## Pre-Publishing Checklist

- [x] package.json configured correctly
- [x] CLI binary (`bin/clawproof.js`) created and executable
- [x] Core library (`dist/index.js`) implemented
- [x] README.md with comprehensive documentation
- [x] LICENSE file (MIT)
- [x] .gitignore and .npmignore configured
- [ ] Tests added (optional for v1.0.0)
- [x] Validated CLI works correctly

## Publishing Steps

### 1. Create npm Account

```bash
npm adduser
# or
npm login
```

### 2. Verify Package Contents

```bash
cd clawproof
npm pack --dry-run
```

This shows what files will be included in the package.

### 3. Test Locally

```bash
# Link package locally
npm link

# Test in another directory
cd /tmp
clawproof help
clawproof scan-text "test prompt"

# Unlink when done
npm unlink -g clawproof
```

### 4. Publish to npm

```bash
cd clawproof

# Publish
npm publish

# For scoped package (recommended)
npm publish --access public
```

### 5. Verify Publication

```bash
# Install from npm
npm install -g clawproof

# Test
clawproof help
```

## Post-Publishing

### Update README Badges

Add to README.md:

```markdown
[![npm version](https://badge.fury.io/js/clawproof.svg)](https://badge.fury.io/js/clawproof)
[![npm downloads](https://img.shields.io/npm/dm/clawproof.svg)](https://www.npmjs.com/package/clawproof)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

### Create GitHub Repository

```bash
# Initialize git if not already done
git init
git add .
git commit -m "Initial commit - ClawProof v1.0.0"

# Add remote
git remote add origin https://github.com/sinewaveai/agent-security-scanner-mcp.git
git branch -M main
git push -u origin main
```

### Tag Release

```bash
git tag -a v1.0.0 -m "Release v1.0.0 - First stable release"
git push origin v1.0.0
```

## Package URL

Once published:
- **npm:** https://www.npmjs.com/package/clawproof
- **GitHub:** https://github.com/sinewaveai/agent-security-scanner-mcp

## Installation for Users

```bash
# Global installation
npm install -g clawproof

# Local installation
npm install clawproof

# Usage
clawproof scan ./SKILL.md
```

## Version Updates

For future releases:

```bash
# Patch release (1.0.1) - bug fixes
npm version patch

# Minor release (1.1.0) - new features
npm version minor

# Major release (2.0.0) - breaking changes
npm version major

# Publish updated version
npm publish
```

## Package Stats

After publishing, track:
- npm downloads: https://npm-stat.com/charts.html?package=clawproof
- Package health: https://snyk.io/advisor/npm-package/clawproof
- Bundle size: https://bundlephobia.com/package/clawproof

## Marketing & Promotion

### Announce on:
- Twitter/X with #ai-security, #llm-security
- Hacker News
- Reddit: r/MachineLearning, r/javascript
- Dev.to blog post
- Product Hunt launch

### Write Blog Posts:
1. "Introducing ClawProof: The First Security Scanner for AI Agent Skills"
2. "Why 69.5% of ClawHub Skills Have Security Issues"
3. "How to Protect Your AI Agents from Prompt Injection"

## Support

- GitHub Issues: https://github.com/sinewaveai/agent-security-scanner-mcp/issues
- Discussions: https://github.com/sinewaveai/agent-security-scanner-mcp/discussions
- Website: https://sinewave.ai

## License

MIT - See LICENSE file
