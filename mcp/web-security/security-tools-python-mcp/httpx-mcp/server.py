#!/usr/bin/env python3
"""
Httpx MCP Server
A Model Context Protocol server that provides Httpx functionality for HTTP service discovery and probing.
"""

import sys
import subprocess
import asyncio
import re
from typing import List, Optional
from mcp.server.fastmcp import FastMCP

# Check if httpx binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <httpx binary>", file=sys.stderr)
    sys.exit(1)

httpx_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("httpx", version="1.0.0")

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B\[[0-9;]*m')
    return ansi_escape.sub('', text)

@mcp.tool()
async def httpx(target: List[str], ports: Optional[List[int]] = None, probes: Optional[List[str]] = None) -> str:
    """Scans the given target domains and detects active HTTP/HTTPS services on ports like 80 and 443.
    
    Args:
        target: A list of domain names (e.g., example.com) to scan for HTTP and HTTPS services.
        ports: List of ports to scan (optional)
        probes: Available probe options:
            status-code      Display response status-code
            content-length   Display response content-length
            content-type     Display response content-type
            location         Display response redirect location
            favicon          Display mmh3 hash for '/favicon.ico' file
            hash             Display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)
            jarm             Display jarm fingerprint hash
            response-time    Display response time
            line-count       Display response body line count
            word-count       Display response body word count
            title            Display page title
            body-preview     Display first N characters of response body (default 100)
            web-server       Display server name
            tech-detect      Display technology in use based on wappalyzer dataset
            method           Display http request method
            websocket        Display server using websocket
            ip               Display host ip
            cname            Display host cname
            extract-fqdn     Get domain and subdomains from response body and header
            asn              Display host asn information
            cdn              Display cdn/waf in use (default true)
            probe            Display probe status
            
    Returns:
        Results from httpx scan showing active HTTP/HTTPS services
    """
    try:
        # Construct the command
        cmd = [httpx_command, "-u", ",".join(target), "-silent"]
        
        # Add ports if specified
        if ports and len(ports) > 0:
            cmd.extend(["-p", ",".join(map(str, ports))])
        
        # Add probes if specified
        if probes and len(probes) > 0:
            for probe in probes:
                cmd.append(f"-{probe}")
        
        # Execute httpx command
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
            return f"httpx exited with code {process.returncode}\nOutput:\n{clean_output}"
            
    except Exception as e:
        return f"Failed to start httpx: {str(e)}"

if __name__ == "__main__":
    mcp.run() 