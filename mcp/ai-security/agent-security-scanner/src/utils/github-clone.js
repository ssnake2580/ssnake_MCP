#!/usr/bin/env node

/**
 * github-clone.js
 *
 * Safe GitHub repository cloning WITHOUT code execution
 *
 * Security Features:
 * - Uses --no-checkout to prevent automatic code checkout
 * - Uses git archive to extract files without triggering hooks
 * - No postinstall scripts, no git hooks, no code execution
 * - Size limits to prevent repository bombs
 * - Timeout protection
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';

const execAsync = promisify(exec);

const MAX_REPO_SIZE_MB = 500; // 500MB limit
const CLONE_TIMEOUT_MS = 120000; // 2 minutes
const ARCHIVE_TIMEOUT_MS = 60000; // 1 minute

/**
 * Extract GitHub owner/repo from various URL formats
 * @param {string} url - GitHub URL
 * @returns {{owner: string, repo: string} | null}
 */
export function parseGitHubUrl(url) {
  if (!url) return null;

  // Match patterns:
  // - https://github.com/owner/repo
  // - https://github.com/owner/repo.git
  // - git@github.com:owner/repo.git
  // - github.com/owner/repo
  const patterns = [
    /github\.com[\/:]([^\/]+)\/([^\/\.]+)/,
    /^([^\/]+)\/([^\/]+)$/,  // owner/repo format
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace(/\.git$/, ''),
      };
    }
  }

  return null;
}

/**
 * Clone a GitHub repository safely without checking out files
 * @param {string} repoUrl - GitHub repository URL
 * @param {string} destDir - Destination directory
 * @param {object} options - Options
 * @returns {Promise<{success: boolean, path?: string, error?: string}>}
 */
export async function cloneGitHubRepo(repoUrl, destDir, options = {}) {
  const {
    depth = 1,
    branch = null,
    timeout = CLONE_TIMEOUT_MS,
  } = options;

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return { success: false, error: 'Invalid GitHub URL' };
  }

  const { owner, repo } = parsed;
  const cloneDir = path.join(destDir, `${owner}-${repo}`);

  try {
    // Create destination directory
    await fs.mkdir(destDir, { recursive: true });

    // Build clone command with safety flags
    const branchFlag = branch ? `--branch ${branch}` : '';
    const cloneCmd = `git clone --depth ${depth} --no-checkout ${branchFlag} https://github.com/${owner}/${repo}.git "${cloneDir}"`;

    // Clone without checking out (no hooks triggered)
    const { stdout, stderr } = await execAsync(cloneCmd, {
      timeout,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for git output
    });

    // Check repository size
    const sizeCmd = `du -sm "${cloneDir}" | cut -f1`;
    const { stdout: sizeOutput } = await execAsync(sizeCmd);
    const sizeMB = parseInt(sizeOutput.trim(), 10);

    if (sizeMB > MAX_REPO_SIZE_MB) {
      // Delete oversized repo
      await fs.rm(cloneDir, { recursive: true, force: true });
      return {
        success: false,
        error: `Repository too large: ${sizeMB}MB > ${MAX_REPO_SIZE_MB}MB limit`,
      };
    }

    return {
      success: true,
      path: cloneDir,
      size: sizeMB,
    };

  } catch (error) {
    // Clean up on failure
    if (existsSync(cloneDir)) {
      await fs.rm(cloneDir, { recursive: true, force: true }).catch(() => {});
    }

    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Extract files from cloned repo using git archive (safe - no hooks)
 * @param {string} repoPath - Path to cloned repository
 * @param {string} extractDir - Directory to extract files to
 * @returns {Promise<{success: boolean, path?: string, error?: string}>}
 */
export async function extractRepoFiles(repoPath, extractDir) {
  try {
    // Create extraction directory
    await fs.mkdir(extractDir, { recursive: true });

    // Use git archive to extract HEAD without triggering any hooks
    const archiveCmd = `cd "${repoPath}" && git archive HEAD | tar -x -C "${extractDir}"`;

    await execAsync(archiveCmd, {
      timeout: ARCHIVE_TIMEOUT_MS,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer
    });

    return {
      success: true,
      path: extractDir,
    };

  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Full workflow: clone + extract + cleanup
 * @param {string} repoUrl - GitHub repository URL
 * @param {string} workDir - Working directory for clone operations
 * @returns {Promise<{success: boolean, sourcePath?: string, error?: string}>}
 */
export async function cloneAndExtract(repoUrl, workDir) {
  const tempCloneDir = path.join(workDir, 'temp-clones');
  const extractDir = path.join(workDir, 'extracted-source');

  try {
    // Step 1: Clone without checkout
    const cloneResult = await cloneGitHubRepo(repoUrl, tempCloneDir);

    if (!cloneResult.success) {
      return cloneResult;
    }

    // Step 2: Extract files safely
    const extractResult = await extractRepoFiles(cloneResult.path, extractDir);

    // Step 3: Clean up clone directory (keep extracted only)
    await fs.rm(tempCloneDir, { recursive: true, force: true });

    if (!extractResult.success) {
      // Clean up extracted files on failure
      await fs.rm(extractDir, { recursive: true, force: true });
      return extractResult;
    }

    return {
      success: true,
      sourcePath: extractDir,
      repoSize: cloneResult.size,
    };

  } catch (error) {
    // Clean up everything on error
    await fs.rm(tempCloneDir, { recursive: true, force: true }).catch(() => {});
    await fs.rm(extractDir, { recursive: true, force: true }).catch(() => {});

    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Check if a URL is a valid GitHub repository (without cloning)
 * @param {string} url - URL to check
 * @returns {Promise<boolean>}
 */
export async function isValidGitHubRepo(url) {
  const parsed = parseGitHubUrl(url);
  if (!parsed) return false;

  const { owner, repo } = parsed;

  try {
    // Check if repo exists using git ls-remote (lightweight)
    const checkCmd = `git ls-remote https://github.com/${owner}/${repo}.git HEAD`;
    await execAsync(checkCmd, { timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}
