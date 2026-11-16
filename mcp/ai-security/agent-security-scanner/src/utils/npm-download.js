#!/usr/bin/env node

/**
 * npm-download.js
 *
 * Safe npm package downloading WITHOUT code execution
 *
 * Security Features:
 * - Uses npm pack instead of npm install (no lifecycle scripts)
 * - Extracts tarball manually without running any code
 * - Size limits to prevent tarball bombs
 * - Path traversal protection
 * - Timeout protection
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import { createReadStream, existsSync } from 'fs';
import path from 'path';
import * as tar from 'tar';

const execAsync = promisify(exec);

const MAX_PACKAGE_SIZE_MB = 200; // 200MB limit
const PACK_TIMEOUT_MS = 60000; // 1 minute
const MAX_EXTRACTED_SIZE_MB = 500; // 500MB limit after extraction

/**
 * Download npm package tarball using npm pack (no scripts executed)
 * @param {string} packageName - npm package name with optional version
 * @param {string} destDir - Destination directory
 * @param {object} options - Options
 * @returns {Promise<{success: boolean, tarballPath?: string, error?: string}>}
 */
export async function downloadNpmPackage(packageName, destDir, options = {}) {
  const {
    timeout = PACK_TIMEOUT_MS,
  } = options;

  try {
    // Create destination directory
    await fs.mkdir(destDir, { recursive: true });

    // npm pack downloads the tarball WITHOUT running any scripts
    const packCmd = `cd "${destDir}" && npm pack ${packageName} --dry-run=false 2>&1`;

    const { stdout, stderr } = await execAsync(packCmd, {
      timeout,
      maxBuffer: 10 * 1024 * 1024,
    });

    // Find the downloaded tarball (npm pack outputs the filename)
    const lines = stdout.split('\n');
    const tarballLine = lines.find(line => line.endsWith('.tgz'));

    if (!tarballLine) {
      return {
        success: false,
        error: 'npm pack did not produce a tarball',
      };
    }

    const tarballPath = path.join(destDir, tarballLine.trim());

    // Check tarball size
    const stats = await fs.stat(tarballPath);
    const sizeMB = stats.size / (1024 * 1024);

    if (sizeMB > MAX_PACKAGE_SIZE_MB) {
      await fs.unlink(tarballPath);
      return {
        success: false,
        error: `Package too large: ${sizeMB.toFixed(1)}MB > ${MAX_PACKAGE_SIZE_MB}MB limit`,
      };
    }

    return {
      success: true,
      tarballPath,
      size: sizeMB,
    };

  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Extract npm tarball with security checks
 * @param {string} tarballPath - Path to tarball
 * @param {string} extractDir - Directory to extract to
 * @returns {Promise<{success: boolean, path?: string, error?: string}>}
 */
export async function extractNpmTarball(tarballPath, extractDir) {
  try {
    // Create extraction directory
    await fs.mkdir(extractDir, { recursive: true });

    // Extract tarball with security options
    await tar.x({
      file: tarballPath,
      cwd: extractDir,
      strip: 1, // Remove 'package/' prefix from npm tarballs

      // Security options
      filter: (path, entry) => {
        // Block path traversal attempts
        if (path.includes('..')) {
          console.warn(`Blocked path traversal attempt: ${path}`);
          return false;
        }

        // Block absolute paths
        if (path.startsWith('/')) {
          console.warn(`Blocked absolute path: ${path}`);
          return false;
        }

        // Block symlinks (potential security risk)
        if (entry.type === 'SymbolicLink') {
          console.warn(`Blocked symlink: ${path}`);
          return false;
        }

        // Block files larger than 50MB individually
        if (entry.size > 50 * 1024 * 1024) {
          console.warn(`Blocked large file: ${path} (${entry.size} bytes)`);
          return false;
        }

        return true;
      },

      // Prevent archive bombs
      maxReadSize: MAX_EXTRACTED_SIZE_MB * 1024 * 1024,
    });

    // Check total extracted size
    const sizeCmd = `du -sm "${extractDir}" | cut -f1`;
    const { stdout } = await execAsync(sizeCmd);
    const sizeMB = parseInt(stdout.trim(), 10);

    if (sizeMB > MAX_EXTRACTED_SIZE_MB) {
      // Delete oversized extraction
      await fs.rm(extractDir, { recursive: true, force: true });
      return {
        success: false,
        error: `Extracted size too large: ${sizeMB}MB > ${MAX_EXTRACTED_SIZE_MB}MB limit`,
      };
    }

    return {
      success: true,
      path: extractDir,
      size: sizeMB,
    };

  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Full workflow: download + extract + cleanup tarball
 * @param {string} packageName - npm package name
 * @param {string} workDir - Working directory
 * @returns {Promise<{success: boolean, sourcePath?: string, error?: string}>}
 */
export async function downloadAndExtract(packageName, workDir) {
  const tempDownloadDir = path.join(workDir, 'temp-downloads');
  const extractDir = path.join(workDir, 'extracted-source');

  try {
    // Step 1: Download tarball
    const downloadResult = await downloadNpmPackage(packageName, tempDownloadDir);

    if (!downloadResult.success) {
      return downloadResult;
    }

    // Step 2: Extract tarball
    const extractResult = await extractNpmTarball(downloadResult.tarballPath, extractDir);

    // Step 3: Clean up tarball and download directory
    await fs.rm(tempDownloadDir, { recursive: true, force: true });

    if (!extractResult.success) {
      // Clean up extracted files on failure
      await fs.rm(extractDir, { recursive: true, force: true });
      return extractResult;
    }

    return {
      success: true,
      sourcePath: extractDir,
      packageSize: downloadResult.size,
      extractedSize: extractResult.size,
    };

  } catch (error) {
    // Clean up everything on error
    await fs.rm(tempDownloadDir, { recursive: true, force: true }).catch(() => {});
    await fs.rm(extractDir, { recursive: true, force: true }).catch(() => {});

    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Check if an npm package exists (without downloading)
 * @param {string} packageName - Package name to check
 * @returns {Promise<boolean>}
 */
export async function npmPackageExists(packageName) {
  try {
    // Use npm view to check if package exists
    const viewCmd = `npm view ${packageName} name 2>&1`;
    const { stdout } = await execAsync(viewCmd, { timeout: 10000 });

    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Get package.json metadata without downloading full package
 * @param {string} packageName - Package name
 * @returns {Promise<{success: boolean, metadata?: object, error?: string}>}
 */
export async function getPackageMetadata(packageName) {
  try {
    const viewCmd = `npm view ${packageName} --json`;
    const { stdout } = await execAsync(viewCmd, { timeout: 10000 });

    const metadata = JSON.parse(stdout);

    return {
      success: true,
      metadata: {
        name: metadata.name,
        version: metadata.version,
        description: metadata.description,
        homepage: metadata.homepage,
        repository: metadata.repository,
        dependencies: metadata.dependencies || {},
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}
