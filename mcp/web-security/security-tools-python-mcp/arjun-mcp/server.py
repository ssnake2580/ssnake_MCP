#!/usr/bin/env python3
"""
Arjun MCP Server
A Model Context Protocol server that provides Arjun functionality for discovering hidden HTTP parameters.
"""

import sys
import subprocess
import asyncio
from typing import Optional
from enum import Enum
from mcp.server.fastmcp import FastMCP

# Check if arjun binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <arjun binary or python3 arjun>", file=sys.stderr)
    sys.exit(1)

arjun_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("arjun", version="1.0.0")

class ArjunMethod(str, Enum):
    """HTTP methods supported by Arjun"""
    GET = "GET"
    POST = "POST"
    JSON = "JSON"
    HEADERS = "HEADERS"

@mcp.tool()
async def do_arjun(
    url: Optional[str] = None,
    textFile: Optional[str] = None,
    wordlist: Optional[str] = None,
    method: Optional[ArjunMethod] = None,
    rateLimit: Optional[int] = None,
    chunkSize: Optional[int] = None
) -> str:
    """Run Arjun to discover hidden HTTP parameters
    
    Args:
        url: Target URL to scan for hidden parameters
        textFile: Path to file containing multiple URLs
        wordlist: Path to custom wordlist file
        method: HTTP method to use for scanning (default: GET)
        rateLimit: Maximum requests per second (default: 9999)
        chunkSize: Chunk size. The number of parameters to be sent at once
        
    Returns:
        Discovered hidden HTTP parameters and analysis results
    """
    try:
        # Build command arguments
        arjun_args = []
        
        if not url and not textFile:
            return "Error: url or textFile parameter required"
            
        if url:
            arjun_args.extend(['-u', url])
            
        if textFile:
            arjun_args.extend(['-f', textFile])
            
        if wordlist:
            arjun_args.extend(['-w', wordlist])
            
        if method:
            arjun_args.extend(['-m', method.value])
            
        if rateLimit:
            arjun_args.extend(['--rate-limit', str(rateLimit)])
            
        if chunkSize:
            arjun_args.extend(['--chunk-size', str(chunkSize)])
            
        # Execute arjun command
        process = await asyncio.create_subprocess_exec(
            arjun_command,
            *arjun_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout
        else:
            return f"arjun exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start arjun: {str(e)}"

if __name__ == "__main__":
    mcp.run() 