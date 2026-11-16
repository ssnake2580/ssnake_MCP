#!/usr/bin/env node
/**
 * Helper script to scan a file via the daemon (for demo purposes)
 * This ensures the scan goes through the daemon's LRU cache
 */

import { getDaemonClient } from '../src/daemon-client.js';

async function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: node scan-via-daemon.js <file_path>');
    process.exit(1);
  }

  try {
    const daemon = getDaemonClient();
    const result = await daemon.analyze(filePath, 'auto');

    // Output raw JSON for compatibility with demo script
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

main();
