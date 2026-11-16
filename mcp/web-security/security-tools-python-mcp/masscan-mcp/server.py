#!/usr/bin/env python3
"""
Masscan MCP Server
A Model Context Protocol server that provides Masscan functionality for high-speed port scanning.
"""

import sys
import subprocess
import asyncio
from typing import List
from mcp.server.fastmcp import FastMCP

# Check if masscan binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <masscan binary>", file=sys.stderr)
    sys.exit(1)

masscan_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("masscan", version="1.0.0")

@mcp.tool()
async def do_masscan(target: str, port: str, masscan_args: List[str] = None) -> str:
    """Run masscan with specified target MASSCAN is a fast port scanner. The primary input parameters are the IP addresses/ranges you want to scan, and the port numbers.
    
    Args:
        target: Target information. Example: 1.1.1.1
        port: Target port. Example: 1234 or 0-65535
        masscan_args: Additional masscan arguments
            --max-rate: Maximum packets per second to send
            --rate: Packets per second (legacy option)
            --banners: Retrieve banner information
            --excludefile: Exclude IP addresses from a file
            --includefile: Include IP addresses from a file
            --randomize-hosts: Randomize the order of scanning hosts
            --wait: Time to wait for response packets (default 10 seconds)
            --retries: Number of times to resend packets (default 3)
            --interactive: Real-time output
            --output-format: json, xml, list, grepable
            --output-filename: Output to a file
            
    Returns:
        Results from masscan high-speed port scan
    """
    if masscan_args is None:
        masscan_args = []
    
    try:
        # Construct the command - port with -p prefix, target, then additional args
        cmd = [masscan_command, f"-p{port}", target] + masscan_args
        
        # Execute masscan command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n masscan completed successfully"
        else:
            return f"masscan exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start masscan: {str(e)}"

if __name__ == "__main__":
    mcp.run() 