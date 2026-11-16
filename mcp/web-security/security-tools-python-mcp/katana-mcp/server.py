#!/usr/bin/env python3
"""
Katana MCP Server
A Model Context Protocol server that provides Katana functionality for web crawling and endpoint discovery.
"""

import sys
import os
import asyncio
import re
from typing import List, Optional
from enum import Enum
from mcp.server.fastmcp import FastMCP

# Check if katana binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <katana binary>", file=sys.stderr)
    sys.exit(1)

katana_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("katana", version="1.0.0")

class CrawlStrategy(str, Enum):
    """Crawling strategies supported by Katana"""
    DEPTH_FIRST = "depth-first"
    BREADTH_FIRST = "breadth-first"

def remove_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_pattern = re.compile(r'\x1B\[[0-9;]*m')
    return ansi_pattern.sub('', text)

@mcp.tool()
async def do_katana(
    target: List[str],
    exclude: Optional[List[str]] = None,
    depth: Optional[int] = None,
    js_crawl: Optional[bool] = None,
    jsluice: Optional[bool] = None,
    headers: Optional[List[str]] = None,
    strategy: Optional[CrawlStrategy] = None,
    headless: Optional[bool] = None,
    system_chrome: Optional[bool] = None,
    show_browser: Optional[bool] = None
) -> str:
    """Performs fast and configurable web crawling on the given target URLs, identifying endpoints, parameters, and JS-based links.
    
    Args:
        target: List of target URLs (e.g., https://example.com) to scan for endpoints and JavaScript-based links.
        exclude: List of URLs or regex patterns to exclude from crawling.
        depth: Maximum crawl depth (e.g., 3 for three levels deep).
        js_crawl: Enable crawling and endpoint extraction from JavaScript files.
        jsluice: Enable JSluice parsing for deeper JavaScript-based link analysis (memory intensive).
        headers: List of custom headers or cookies to include in requests (format: Header:Value).
        strategy: Crawling strategy to use: 'depth-first' or 'breadth-first' (default is depth-first).
        headless: Enable headless browser-based hybrid crawling (experimental).
        system_chrome: Use the locally installed Chrome browser instead of the built-in one.
        show_browser: Show the browser window even in headless mode (for debugging/visual inspection).
        
    Returns:
        Discovered URLs, endpoints, and parameters from the crawled targets
    """
    try:
        # Construct the command arguments
        katana_args = ["-u", ",".join(target), "-silent"]
        
        if exclude:
            katana_args.extend(["-exclude", ",".join(exclude)])
            
        if depth is not None:
            katana_args.extend(["-d", str(depth)])
            
        if js_crawl:
            katana_args.append("-jc")
            
        if jsluice:
            katana_args.append("-jsl")
            
        if headers:
            for header in headers:
                katana_args.extend(["-H", header])
                
        if strategy:
            katana_args.extend(["-strategy", strategy.value])
            
        if headless:
            katana_args.append("-headless")
            
        if system_chrome:
            katana_args.append("-system-chrome")
            
        if show_browser:
            katana_args.append("-show-browser")
        
        # For PTY-like behavior, we use subprocess with a pseudo-terminal
        # This is needed because Katana has interactive output
        process = await asyncio.create_subprocess_exec(
            katana_command,
            *katana_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # Enable unbuffered output
            env={**os.environ, "PYTHONUNBUFFERED": "1"}
        )
        
        # Collect all output
        output = ""
        while True:
            # Read chunk by chunk to handle live output
            chunk = await process.stdout.read(4096)
            if not chunk:
                break
            output += chunk.decode('utf-8', errors='replace')
        
        # Wait for process to complete
        await process.wait()
        
        # Remove ANSI color codes
        clean_output = remove_ansi_codes(output)
        
        if process.returncode == 0:
            return clean_output
        else:
            return f"katana exited with code {process.returncode}\nOutput:\n{clean_output}"
            
    except Exception as e:
        return f"Failed to start katana: {str(e)}"

if __name__ == "__main__":
    mcp.run() 