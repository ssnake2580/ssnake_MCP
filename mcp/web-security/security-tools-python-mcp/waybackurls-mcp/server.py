#!/usr/bin/env python3
"""
Waybackurls MCP Server
A Model Context Protocol server that provides Waybackurls functionality for discovering historical URLs.
"""

import sys
import subprocess
import asyncio
from typing import Optional
from mcp.server.fastmcp import FastMCP

# Check if waybackurls binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <waybackurls binary>", file=sys.stderr)
    sys.exit(1)

waybackurls_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("waybackurls", version="1.0.0")

@mcp.tool()
async def do_waybackurls(target: str, noSub: Optional[bool] = None) -> str:
    """Execute Waybackurls, a tool that fetches known URLs from the Wayback Machine archive for a given domain. This helps in discovering historical endpoints, forgotten API paths, and potentially vulnerable URLs that might not be directly accessible or linked from the current version of the website.
    
    Args:
        target: Target domain to retrieve historical URLs from the Wayback Machine (e.g., example.com)
        noSub: When set to true, only retrieves URLs from the exact domain specified, excluding all subdomains
        
    Returns:
        Historical URLs discovered from the Wayback Machine
    """
    try:
        # Construct the command
        cmd = [waybackurls_command, target]
        
        # Add --no-subs flag if requested
        if noSub:
            cmd.append("--no-subs")
        
        # Execute waybackurls command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n waybackurls completed successfully"
        else:
            return f"waybackurls exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start waybackurls: {str(e)}"

if __name__ == "__main__":
    mcp.run() 