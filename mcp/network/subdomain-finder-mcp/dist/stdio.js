#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './tools.js';
import { fetchNode } from './fetch-node.js';
const server = createServer(fetchNode);
await server.connect(new StdioServerTransport());
