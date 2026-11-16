#!/usr/bin/env python3
"""
WPScan MCP Server
A Model Context Protocol server that provides WPScan functionality for WordPress security scanning.
"""

import sys
import asyncio
from typing import List, Optional, Literal
from mcp.server.fastmcp import FastMCP

# Check if wpscan binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <wpscan binary>", file=sys.stderr)
    sys.exit(1)

wpscan_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("wpscan", version="1.0.0")

@mcp.tool()
async def do_wpscan(
    url: str,
    detection_mode: Optional[Literal["mixed", "passive", "aggressive"]] = None,
    random_user_agent: Optional[bool] = None,
    max_threads: Optional[int] = None,
    disable_tls_checks: Optional[bool] = None,
    proxy: Optional[str] = None,
    cookies: Optional[str] = None,
    force: Optional[bool] = None,
    enumerate: Optional[List[Literal["vp", "ap", "p", "vt", "at", "t", "tt", "cb", "dbe"]]] = None
) -> str:
    """Run wpscan to analyze wordpress web sites
    
    Args:
        url: The target WordPress website URL to scan. Must be a valid URL starting with http:// or https://
        detection_mode: Scan detection mode: 'mixed' (default) combines passive and aggressive, 'passive' for non-intrusive scanning, 'aggressive' for thorough but potentially detectable scanning
        random_user_agent: Enable random user agent rotation for each request to avoid detection
        max_threads: Maximum number of concurrent scanning threads. Default is 5. Higher values increase speed but may trigger rate limiting
        disable_tls_checks: Disable SSL/TLS certificate verification and allow TLS 1.0+ connections. Requires cURL 7.66 or higher for TLS downgrade support
        proxy: Proxy server to route requests through. Format: protocol://IP:port (e.g., http://127.0.0.1:8080). Supported protocols depend on installed cURL version
        cookies: Custom cookies to include in requests. Format: name1=value1; name2=value2. Useful for authenticated scanning
        force: Skip WordPress detection and 403 response checks. Use when you're certain the target is WordPress
        enumerate: WordPress enumeration options:
            - vp: Scan for vulnerable plugins
            - ap: Scan all installed plugins
            - p:  Scan only popular plugins
            - vt: Scan for vulnerable themes
            - at: Scan all installed themes
            - t:  Scan only popular themes
            - tt: Scan for timthumb vulnerabilities
            - cb: Scan for configuration backups
            - dbe: Scan for database exports

            Note: Some options are mutually exclusive:
            - Only one of vp, ap, p can be used
            - Only one of vt, at, t can be used

            Default behavior if not specified: vp,vt,tt,cb,dbe,u,m
        
    Returns:
        The output from wpscan execution
    """
    
    # Basic URL validation
    if not url.startswith(('http://', 'https://')):
        return "Error: URL must start with http:// or https://"
    
    # Build wpscan command arguments
    wpscan_args = ['-u', url]

    # Add detection mode if specified
    if detection_mode:
        wpscan_args.extend(['--detection-mode', detection_mode])

    # Add random user agent if specified
    if random_user_agent:
        wpscan_args.append('--random-user-agent')

    # Add max threads if specified
    if max_threads:
        wpscan_args.extend(['-t', str(max_threads)])

    # Add disable TLS checks if specified
    if disable_tls_checks:
        wpscan_args.append('--disable-tls-checks')

    # Add proxy if specified
    if proxy:
        wpscan_args.extend(['--proxy', proxy])

    # Add cookies if specified
    if cookies:
        wpscan_args.extend(['--cookie-string', cookies])

    # Add force if specified
    if force:
        wpscan_args.append('--force')

    # Add enumerate options if specified
    if enumerate and len(enumerate) > 0:
        wpscan_args.extend(['-e', ','.join(enumerate)])

    try:
        # Execute wpscan command
        process = await asyncio.create_subprocess_exec(
            wpscan_command,
            *wpscan_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n wpscan completed successfully"
        else:
            return f"wpscan exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start wpscan: {str(e)}"

if __name__ == "__main__":
    mcp.run() 