#!/usr/bin/env python3
"""
Amass MCP Server
A Model Context Protocol server that provides Amass functionality for advanced subdomain enumeration and reconnaissance.
"""

import sys
import subprocess
import asyncio
from typing import Optional
from enum import Enum
from mcp.server.fastmcp import FastMCP

# Check if amass binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <amass binary>", file=sys.stderr)
    sys.exit(1)

amass_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("amass", version="1.0.0")

class AmassSubcommand(str, Enum):
    """Amass operation modes"""
    enum = "enum"
    intel = "intel"

class AmassEnumType(str, Enum):
    """Enumeration approach types"""
    active = "active"
    passive = "passive"

@mcp.tool()
async def amass(
    subcommand: AmassSubcommand,
    domain: Optional[str] = None,
    intel_whois: Optional[bool] = None,
    intel_organization: Optional[str] = None,
    enum_type: Optional[AmassEnumType] = None,
    enum_brute: Optional[bool] = None,
    enum_brute_wordlist: Optional[str] = None
) -> str:
    """Advanced subdomain enumeration and reconnaissance tool
    
    Args:
        subcommand: Specify the Amass operation mode:
            - intel: Gather intelligence about target domains from various sources
            - enum: Perform subdomain enumeration and network mapping
        domain: Target domain to perform reconnaissance against (e.g., example.com)
        intel_whois: Whether to include WHOIS data in intelligence gathering (true/false)
        intel_organization: Organization name to search for during intelligence gathering (e.g., 'Example Corp')
        enum_type: Enumeration approach type:
            - active: Includes DNS resolution and potential network interactions with target
            - passive: Only uses information from third-party sources without direct target interaction
        enum_brute: Whether to perform brute force subdomain discovery (true/false)
        enum_brute_wordlist: Path to custom wordlist file for brute force operations (e.g., '/path/to/wordlist.txt')
        
    Returns:
        Results from amass reconnaissance and enumeration
    """
    try:
        # Initialize command arguments
        amass_args = [subcommand.value]
        
        # Handle different subcommands
        if subcommand == AmassSubcommand.enum:
            if not domain:
                return "Error: Domain parameter is required for 'enum' subcommand"
            
            amass_args.extend(["-d", domain])
            
            # Handle enum type
            if enum_type == AmassEnumType.passive:
                amass_args.append("-passive")
            # Active is default for enum, no flag needed
            
            # Handle brute force options
            if enum_brute:
                amass_args.append("-brute")
                
                # Add custom wordlist if provided
                if enum_brute_wordlist:
                    amass_args.extend(["-w", enum_brute_wordlist])
                    
        elif subcommand == AmassSubcommand.intel:
            if not domain and not intel_organization:
                return "Error: Either domain or organization parameter is required for 'intel' subcommand"
            
            # Add domain if provided
            if domain:
                amass_args.extend(["-d", domain])
                # For domain intel, whois is typically required
                if intel_whois is not True:
                    return "Error: For domain parameter whois is required"
            
            # Add organization if provided
            if intel_organization:
                amass_args.extend(["-org", f"'{intel_organization}'"])
            
            # Add whois option if enabled
            if intel_whois:
                amass_args.append("-whois")
        
        print(f"Executing: amass {' '.join(amass_args)}")
        
        # Execute amass command
        process = await asyncio.create_subprocess_exec(
            amass_command,
            *amass_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout.strip()
        else:
            return f"Amass exited with code {process.returncode}. Output: {stdout}. Args: {amass_args}"
            
    except Exception as e:
        return f"Failed to start Amass: {str(e)}"

if __name__ == "__main__":
    mcp.run() 