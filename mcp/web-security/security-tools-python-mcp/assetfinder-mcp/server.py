#!/usr/bin/env python3
"""
Assetfinder MCP Server
A Model Context Protocol server that provides Assetfinder functionality for subdomain discovery.
"""

import sys
import subprocess
import asyncio
import re
from mcp.server.fastmcp import FastMCP

# Check if assetfinder binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <assetfinder binary>", file=sys.stderr)
    sys.exit(1)

assetfinder_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("assetfinder", version="1.0.0")

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*m')
    return ansi_escape.sub('', text)

@mcp.tool()
async def do_assetfinder(target: str) -> str:
    """Find related domains and subdomains using assetfinder for a given target.
    
    Args:
        target: The root domain (e.g., example.com) to discover associated subdomains and related domains.
        
    Returns:
        List of discovered subdomains and related domains
    """
    try:
        # Construct the command with -subs-only flag
        cmd = [assetfinder_command, "-subs-only", target]
        
        # Execute assetfinder command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        # Remove ANSI color codes
        clean_output = remove_ansi_codes(stdout)
        
        if process.returncode == 0 or process.returncode is None:
            return clean_output.strip()
        else:
            return f"assetfinder exited with code {process.returncode}\nOutput:\n{clean_output}"
            
    except Exception as e:
        return f"Failed to start assetfinder: {str(e)}"

if __name__ == "__main__":
    mcp.run() 