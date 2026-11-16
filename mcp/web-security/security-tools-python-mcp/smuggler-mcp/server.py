#!/usr/bin/env python3
"""
Smuggler MCP Server
A Model Context Protocol server that provides Smuggler functionality for detecting HTTP Request Smuggling vulnerabilities.
"""

import sys
import subprocess
import asyncio
import re
from typing import List, Optional, Dict, Any
from mcp.server.fastmcp import FastMCP

# Check if python path and smuggler.py path are provided
if len(sys.argv) != 3:
    print("Usage: python server.py <python path> <smuggler.py path>", file=sys.stderr)
    sys.exit(1)

python_path = sys.argv[1]
smuggler_path = sys.argv[2]

# Create FastMCP server instance
mcp = FastMCP("smuggler", version="1.0.0")

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*[mGK]')
    return ansi_escape.sub('', text)

def parse_results(output: str) -> Dict[str, List[Dict[str, str]]]:
    """Parse smuggler output to extract vulnerability findings."""
    vulnerabilities = {
        "cl_te": [],
        "te_cl": []
    }
    
    # Regex patterns for CL.TE and TE.CL vulnerabilities
    clte_regex = re.compile(r'\[(\+|\!)\] Potential (CL\.TE) Vulnerability Found \((\w+)\)', re.IGNORECASE)
    tecl_regex = re.compile(r'\[(\+|\!)\] Potential (TE\.CL) Vulnerability Found \((\w+)\)', re.IGNORECASE)
    
    # Find CL.TE vulnerabilities
    for match in clte_regex.finditer(output):
        severity = 'high' if match.group(1) == '+' else 'medium'
        mutation = match.group(3)
        vulnerabilities["cl_te"].append({
            "mutation": mutation,
            "severity": severity
        })
    
    # Find TE.CL vulnerabilities
    for match in tecl_regex.finditer(output):
        severity = 'high' if match.group(1) == '+' else 'medium'
        mutation = match.group(3)
        vulnerabilities["te_cl"].append({
            "mutation": mutation,
            "severity": severity
        })
    
    return vulnerabilities

@mcp.tool()
async def do_smuggler(url: str, smuggler_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run Smuggler to detect HTTP Request Smuggling vulnerabilities
    
    Args:
        url: Target URL to detect HTTP Request Smuggling
        smuggler_args: Additional smuggler arguments
            -m, --method METHOD  Specify the HTTP method to use (default: POST)
            -v, --vhost VHOST    Specify a virtual host to use
            -l, --len            Enable Content-Length header in all requests
            -c, --configfile FILE
                                 Specify a configuration file to load payloads from
            -x                   Exit on the first finding
            -t, --timeout TIMEOUT
                                 Socket timeout value (default: 5)
            -verify VERIFY       Verify findings with more requests; never, quick or thorough (default: quick)
    
    Returns:
        Dict containing text output and metadata with vulnerability findings
    """
    if smuggler_args is None:
        smuggler_args = []
    
    try:
        # Construct the command
        base_args = [python_path, smuggler_path, "-u", url]
        cmd = base_args + smuggler_args
        
        # Execute smuggler command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            # Remove ANSI color codes
            clean_output = remove_ansi_codes(stdout)
            
            # Parse vulnerability results
            vuln_results = parse_results(clean_output)
            
            return {
                "content": [{
                    "type": "text",
                    "text": clean_output.strip()
                }],
                "metadata": {
                    "findings": vuln_results
                }
            }
        else:
            raise Exception(f"Smuggler exited with code {process.returncode}")
            
    except Exception as e:
        return {
            "content": [{
                "type": "text", 
                "text": f"Failed to start Smuggler: {str(e)}"
            }],
            "metadata": {
                "findings": {"cl_te": [], "te_cl": []}
            }
        }

if __name__ == "__main__":
    mcp.run() 