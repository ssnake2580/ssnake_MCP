#!/usr/bin/env python3
"""
SQLMap MCP Server
A Model Context Protocol server that provides SQLMap functionality for SQL injection testing.
"""

import sys
import subprocess
import asyncio
from typing import List
from mcp.server.fastmcp import FastMCP

# Check if sqlmap binary/command is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <sqlmap binary or python3 sqlmap>", file=sys.stderr)
    sys.exit(1)

sqlmap_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("sqlmap", version="1.0.0")

@mcp.tool()
async def do_sqlmap(url: str, sqlmap_args: List[str] = None) -> str:
    """Run sqlmap with specified URL
    
    Args:
        url: Target URL to detect SQL Injection
        sqlmap_args: Additional SQLmap arguments 
            
            -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --wizard            Simple wizard interface for beginner users
    
    Returns:
        The output from sqlmap execution
    """
    if sqlmap_args is None:
        sqlmap_args = []
    
    try:
        # Construct the command
        cmd = [sqlmap_command, '-u', url] + sqlmap_args
        
        # Execute sqlmap command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n sqlmap completed successfully"
        else:
            return f"sqlmap exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start sqlmap: {str(e)}"

if __name__ == "__main__":
    mcp.run() 