#!/usr/bin/env python3
"""
Nuclei MCP Server
A Model Context Protocol server that provides Nuclei functionality for vulnerability scanning.
"""

import sys
import subprocess
import asyncio
import json
import re
from typing import List, Optional
import aiohttp
from mcp.server.fastmcp import FastMCP

# Check if nuclei binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <nuclei binary>", file=sys.stderr)
    sys.exit(1)

nuclei_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("nuclei", version="1.0.0")

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*m')
    return ansi_escape.sub('', text)

@mcp.tool()
async def do_nuclei(url: str, tags: Optional[List[str]] = None) -> str:
    """Execute Nuclei, an advanced vulnerability scanner that uses YAML-based templates to detect security vulnerabilities, misconfigurations, and exposures in web applications and infrastructure. Nuclei offers fast scanning with a vast template library covering various security checks.
    
    Args:
        url: Target URL to run nuclei
        tags: Tags to run nuclei for multiple choise use ,
        
    Returns:
        Results from nuclei vulnerability scan
    """
    try:
        # Construct the command
        cmd = [nuclei_command, "-u", url, "-silent"]
        
        # Add tags if specified
        if tags and len(tags) > 0:
            cmd.extend(["-tags", ",".join(tags)])
        
        # Execute nuclei command
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
            return f"nuclei exited with code {process.returncode}\nOutput:\n{clean_output}"
            
    except Exception as e:
        return f"Failed to start nuclei: {str(e)}"

@mcp.tool()
async def get_nuclei_tags() -> str:
    """Get Nuclei Tags
    
    Returns:
        JSON formatted list of available nuclei tags from the official template repository
    """
    try:
        url = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/TEMPLATES-STATS.json"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if not response.ok:
                    return f"Failed to fetch nuclei tags: HTTP {response.status}"
                
                data = await response.json()
                
                # Extract tag names from the response
                if 'tags' in data and isinstance(data['tags'], list):
                    tag_names = [tag.get('name', '') for tag in data['tags'] if 'name' in tag]
                    return json.dumps(tag_names, indent=2)
                else:
                    return "Unable to parse nuclei tags from response"
                    
    except Exception as e:
        return f"Error fetching nuclei tags: {str(e)}"

if __name__ == "__main__":
    mcp.run() 