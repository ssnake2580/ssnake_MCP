#!/usr/bin/env python3
"""
Alterx MCP Server
A Model Context Protocol server that provides Alterx functionality for domain permutation generation.
"""

import sys
import subprocess
import asyncio
from typing import Optional
from mcp.server.fastmcp import FastMCP

# Check if alterx binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <alterx binary>", file=sys.stderr)
    sys.exit(1)

alterx_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("alterx", version="1.0.0")

@mcp.tool()
async def do_alterx(
    domain: str, 
    pattern: str, 
    outputFilePath: Optional[str] = None
) -> str:
    """Execute Alterx, a tool that generates domain wordlists using pattern-based permutations for subdomain discovery and DNS enumeration
    
    Args:
        domain: Target domain or subdomains to use as a base for creating permutations (accepts stdin input, comma-separated values, or file path)
        pattern: Pattern template for generating wordlist variations. Multiple patterns can be specified using comma-separation.
    
            Available pattern types:
            
            - Dash-based patterns (e.g., api-dev.example.com):
              "{{word}}-{{sub}}.{{suffix}}"  // Produces: dev-api.example.com
              "{{sub}}-{{word}}.{{suffix}}"  // Produces: api-dev.example.com
              
            - Dot-based patterns (e.g., dev.api.example.com):
              "{{word}}.{{sub}}.{{suffix}}"  // Produces: word.api.example.com
              "{{sub}}.{{word}}.{{suffix}}"  // Produces: api.word.example.com
              
            - Iteration-based patterns:
              "{{sub}}{{number}}.{{suffix}}"  // Produces: api1.example.com, api2.example.com
              
            - Replacement patterns:
              "{{word}}.{{suffix}}"  // Replaces current subdomain completely
              
            - No separator patterns:
              "{{sub}}{{word}}.{{suffix}}"  // Produces: apidev.example.com
              
            - Region prefix patterns:
              "{{region}}.{{sub}}.{{suffix}}"  // Produces: us-east.api.example.com
              
            - Combination patterns:
              "{{word}}{{number}}.{{suffix}}"  // Combines words and numbers
        outputFilePath: Path where the generated wordlist should be saved (optional)
        
    Returns:
        Generated domain permutations based on the specified pattern
    """
    try:
        # Construct the command arguments
        alterx_args = ["-l", domain, "-p", pattern]
        
        # Add output file path if provided
        if outputFilePath:
            alterx_args.extend(["-o", outputFilePath])
            
        # Execute alterx command
        process = await asyncio.create_subprocess_exec(
            alterx_command,
            *alterx_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n alterx completed successfully"
        else:
            return f"alterx exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start alterx: {str(e)}"

if __name__ == "__main__":
    mcp.run() 