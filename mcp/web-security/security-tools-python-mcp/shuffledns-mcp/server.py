#!/usr/bin/env python3
"""
Shuffledns MCP Server
A Model Context Protocol server that provides Shuffledns functionality for DNS brute force.
"""

import sys
import subprocess
import asyncio
import re
from typing import Optional
from enum import Enum
from mcp.server.fastmcp import FastMCP

# Check if shuffledns and massdns binaries are provided
if len(sys.argv) < 3:
    print("Usage: python server.py <shuffledns binary> <massdns binary>", file=sys.stderr)
    sys.exit(1)

shuffledns_command = sys.argv[1]
massdns_command = sys.argv[2]

# Create FastMCP server instance
mcp = FastMCP("shuffledns", version="1.0.0")

class ShufflednsMode(str, Enum):
    """Shuffledns operation modes"""
    bruteforce = "bruteforce"
    resolve = "resolve"  
    filter = "filter"

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*m')
    return ansi_escape.sub('', text)

@mcp.tool()
async def shuffledns(target: str, resolver: str, mode: ShufflednsMode, wordlist: str, rateLimit: Optional[int] = None) -> str:
    """DNS Brute force
    
    Args:
        target: A list of domain names (e.g., example.com) to scan for HTTP and HTTPS services.
        resolver: Resolver file path
        mode: Mode (bruteforce, resolve, or filter)
        wordlist: wordlist
        rateLimit: ratelimit (optional)
        
    Returns:
        Results from shuffledns DNS brute force operation
    """
    try:
        # Construct the command
        cmd = [
            shuffledns_command,
            "-d", target,
            "-r", resolver,
            "-mode", mode.value,
            "-w", wordlist,
            "-m", massdns_command,
            "-silent"
        ]
        
        # Add rate limit if specified
        if rateLimit:
            cmd.extend(["-t", str(rateLimit)])
        
        # Execute shuffledns command
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
            return f"shuffledns exited with code {process.returncode}\nOutput:\n{clean_output}"
            
    except Exception as e:
        return f"Failed to start shuffledns: {str(e)}"

if __name__ == "__main__":
    mcp.run() 