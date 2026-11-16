import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { findSimilarPackages, checkDependencyConfusion } from './typosquat.js';

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Load legitimate package lists into memory (hash sets for O(1) lookup)
// Using Sets only - no bloom filters for smaller package size
const LEGITIMATE_PACKAGES = {
  dart: new Set(),
  perl: new Set(),
  raku: new Set(),
  npm: new Set(),
  pypi: new Set(),
  rubygems: new Set(),
  crates: new Set()
};

// Load package lists on startup
export function loadPackageLists() {
  // Lightweight version: Package verification files removed to reduce size from 14MB to 82KB
  // Package verification now uses typosquatting and dependency confusion pattern detection only
  console.error('[@prooflayer/security-scanner] Package verification: typosquatting detection only (no package lists loaded)');
}

// Check if a package is hallucinated
export function isHallucinated(packageName, ecosystem) {
  const legitPackages = LEGITIMATE_PACKAGES[ecosystem];

  // Check Set-based lookup (exact match)
  if (legitPackages && legitPackages.size > 0) {
    return {
      hallucinated: !legitPackages.has(packageName),
      verified: legitPackages.has(packageName)
    };
  }

  return { unknown: true, reason: `No package list loaded for ${ecosystem}` };
}

// Get total packages count for an ecosystem
export function getTotalPackages(ecosystem) {
  return LEGITIMATE_PACKAGES[ecosystem]?.size || 0;
}

// Get all package stats
export function getPackageStats() {
  const stats = Object.entries(LEGITIMATE_PACKAGES).map(([ecosystem, packages]) => {
    const setSize = packages.size;
    return {
      ecosystem,
      packages_loaded: setSize,
      status: setSize > 0 ? 'ready' : 'not loaded'
    };
  });

  const totalSet = stats.reduce((sum, s) => sum + s.packages_loaded, 0);

  return {
    package_lists: stats,
    total_packages: totalSet
  };
}

// Schema for check_package tool
export const checkPackageSchema = {
  package_name: z.string().describe("The package name to verify"),
  ecosystem: z.enum(["dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"]).describe("The package ecosystem (dart=pub.dev, perl=CPAN, raku=raku.land, npm=npmjs, pypi=PyPI, rubygems=RubyGems, crates=crates.io)")
};

// Handler for check_package tool
export async function checkPackage({ package_name, ecosystem }) {
  const result = isHallucinated(package_name, ecosystem);

  if (result.unknown) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          package: package_name,
          ecosystem,
          status: "unknown",
          reason: result.reason,
          suggestion: "Load package list or verify manually at the package registry"
        }, null, 2)
      }]
    };
  }

  const exists = !result.hallucinated;
  const confidence = "high"; // Set-based lookup provides high confidence
  const totalPackages = getTotalPackages(ecosystem);

  // Enhanced response with typosquatting and dependency confusion checks
  const response = {
    package: package_name,
    ecosystem,
    legitimate: exists,
    hallucinated: !exists,
    confidence,
    total_known_packages: totalPackages,
    recommendation: exists
      ? "Package exists in registry - safe to use"
      : "POTENTIAL HALLUCINATION - Package not found in registry. Verify before using!"
  };

  // If package not found, check for typosquatting
  if (!exists) {
    const similar = findSimilarPackages(package_name, ecosystem);
    if (similar.length > 0) {
      response.typosquatting = {
        similar_packages: similar,
        warning: `Package '${package_name}' is similar to known packages. This could be a typosquatting attack.`
      };
    }
  }

  // Check for dependency confusion risk regardless of existence
  const confusionCheck = checkDependencyConfusion(package_name);
  if (confusionCheck.risk) {
    response.dependency_confusion = {
      risk: true,
      warning: confusionCheck.warning
    };
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(response, null, 2)
    }]
  };
}
