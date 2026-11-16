#!/usr/bin/env node

// @prooflayer/security-scanner
// Lightweight, zero-Python MCP security scanner for AI coding agents
// MIT License | https://github.com/sinewaveai/agent-security-scanner-mcp

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { getVersion } from './src/utils.js';
import { loadPackageLists } from './src/check-package.js';

// Import tool handlers
import { scanSecurity, scanSecuritySchema } from './src/scan-security.js';
import { fixSecurity, fixSecuritySchema } from './src/fix-security.js';
import { checkPackage, checkPackageSchema } from './src/check-package.js';
import { scanPackages, scanPackagesSchema } from './src/scan-packages.js';
import { scanAgentPrompt, scanAgentPromptSchema } from './src/scan-prompt.js';
import { scanAgentAction, scanAgentActionSchema } from './src/scan-action.js';
import { scanMcpServer, scanMcpServerSchema } from './src/scan-mcp.js';

// Initialize MCP server
const server = new Server(
  {
    name: "@prooflayer/security-scanner",
    version: getVersion(),
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Load package lists on startup (4.3M+ packages)
console.error(`[@prooflayer/security-scanner v${getVersion()}] Loading package verification data...`);
loadPackageLists();
console.error(`[@prooflayer/security-scanner] Ready. Engine: regex (zero-Python)`);

// Register MCP tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "scan_security",
        description: "Scan code for security vulnerabilities using 1700+ YAML rules. Detects SQL injection, XSS, secrets, command injection, and 30+ vulnerability types. Returns findings with severity, line numbers, and auto-fix suggestions.",
        inputSchema: {
          type: "object",
          properties: scanSecuritySchema,
          required: ["file_path"]
        }
      },
      {
        name: "fix_security",
        description: "Generate secure code fixes for vulnerabilities. Provides language-specific remediation for detected issues with explanations.",
        inputSchema: {
          type: "object",
          properties: fixSecuritySchema,
          required: ["file_path"]
        }
      },
      {
        name: "check_package",
        description: "Verify if a package exists in official registries (npm, PyPI, RubyGems, crates.io, CPAN, pub.dev, raku.land). Detects package hallucination and typosquatting. Covers 4.3M+ real packages.",
        inputSchema: {
          type: "object",
          properties: checkPackageSchema,
          required: ["package_name", "ecosystem"]
        }
      },
      {
        name: "scan_packages",
        description: "Scan all package imports in a file for hallucination and typosquatting. Returns verification status for each dependency.",
        inputSchema: {
          type: "object",
          properties: scanPackagesSchema,
          required: ["file_path", "ecosystem"]
        }
      },
      {
        name: "scan_agent_prompt",
        description: "Detect prompt injection, jailbreaks, and social engineering in AI agent prompts. Covers 40+ attack patterns including base64 encoding, role manipulation, and exfiltration attempts.",
        inputSchema: {
          type: "object",
          properties: scanAgentPromptSchema,
          required: ["prompt"]
        }
      },
      {
        name: "scan_agent_action",
        description: "Pre-execution safety check for agent actions (bash, file operations, HTTP requests). Returns ALLOW/WARN/BLOCK with risk assessment.",
        inputSchema: {
          type: "object",
          properties: scanAgentActionSchema,
          required: ["action_type", "action_details"]
        }
      },
      {
        name: "scan_mcp_server",
        description: "Audit MCP server source code for security vulnerabilities, tool name spoofing, description injection, unicode poisoning, and rug pull detection. Returns A-F security grade.",
        inputSchema: {
          type: "object",
          properties: scanMcpServerSchema,
          required: ["server_path"]
        }
      }
    ]
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "scan_security":
        return await scanSecurity(args);

      case "fix_security":
        return await fixSecurity(args);

      case "check_package":
        return await checkPackage(args);

      case "scan_packages":
        return await scanPackages(args);

      case "scan_agent_prompt":
        return await scanAgentPrompt(args);

      case "scan_agent_action":
        return await scanAgentAction(args);

      case "scan_mcp_server":
        return await scanMcpServer(args);

      default:
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }]
        };
    }
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: error.message,
          tool: name,
          timestamp: new Date().toISOString()
        })
      }],
      isError: true
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[@prooflayer/security-scanner] MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
