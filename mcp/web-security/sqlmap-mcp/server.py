#!/usr/bin/env python3
"""
SQLMap MCP Server using FastMCP

This server exposes SQLMap CLI tools as MCP functions for automated SQL injection testing.
"""

import asyncio
import tempfile
import logging
import sys
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


@dataclass
class SqlMapResult:
    """Container for SQLMap command results"""
    success: bool
    output: str
    error: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class SqlMapExecutor:
    """Handles SQLMap command execution"""
    
    def __init__(self):
        self.sqlmap_path = "sqlmap"
    
    async def execute_sqlmap(self, args: List[str], timeout: int = 300) -> SqlMapResult:
        """Execute SQLMap command with given arguments"""
        try:
            cmd = [self.sqlmap_path] + args
            
            # Add batch mode to avoid interactive prompts
            if "--batch" not in args:
                cmd.append("--batch")
            
            logger.info(f"Executing SQLMap command: {' '.join(cmd)}")
            
            # Add output format for better parsing
            if "--output-dir" not in args:
                with tempfile.TemporaryDirectory() as temp_dir:
                    cmd.extend(["--output-dir", temp_dir])
                    result = await asyncio.wait_for(
                        asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            text=False
                        ),
                        timeout=timeout
                    )
                    stdout, stderr = await result.communicate()
                    
                    logger.info(f"SQLMap command completed with return code: {result.returncode}")
                    
                    return SqlMapResult(
                        success=result.returncode == 0,
                        output=stdout.decode('utf-8', errors='ignore') if stdout else "",
                        error=stderr.decode('utf-8', errors='ignore') if stderr else None
                    )
            else:
                result = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        text=False
                    ),
                    timeout=timeout
                )
                stdout, stderr = await result.communicate()
                
                logger.info(f"SQLMap command completed with return code: {result.returncode}")
                
                return SqlMapResult(
                    success=result.returncode == 0,
                    output=stdout.decode('utf-8', errors='ignore') if stdout else "",
                    error=stderr.decode('utf-8', errors='ignore') if stderr else None
                )
                
        except asyncio.TimeoutError:
            logger.error("SQLMap command timed out")
            return SqlMapResult(
                success=False,
                output="",
                error="Command timed out"
            )
        except Exception as e:
            logger.error(f"SQLMap command failed with error: {str(e)}")
            return SqlMapResult(
                success=False,
                output="",
                error=str(e)
            )


# Global SQLMap executor
sqlmap_executor = SqlMapExecutor()

# Initialize FastMCP server
app = FastMCP("sqlmap-mcp")


@app.tool()
async def sqlmap_help(advanced: bool = False) -> str:
    """Show SQLMap help information"""
    args = ["-hh"] if advanced else ["-h"]
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_scan_url(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ"
) -> str:
    """Scan a target URL for SQL injection vulnerabilities"""
    args = ["-u", url]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    if level:
        args.extend(["--level", str(level)])
    if risk:
        args.extend(["--risk", str(risk)])
    if technique:
        args.extend(["--technique", technique])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_enumerate_databases(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Enumerate databases on the target"""
    args = ["-u", url, "--dbs"]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_enumerate_tables(
    url: str,
    database: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Enumerate tables in a specific database"""
    args = ["-u", url, "--tables", "-D", database]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_enumerate_columns(
    url: str,
    database: str,
    table: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Enumerate columns in a specific table"""
    args = ["-u", url, "--columns", "-D", database, "-T", table]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_dump_table(
    url: str,
    database: str,
    table: str,
    columns: Optional[str] = None,
    where: Optional[str] = None,
    limit: Optional[int] = None,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Dump data from a specific table"""
    args = ["-u", url, "--dump", "-D", database, "-T", table]
    
    if columns:
        args.extend(["-C", columns])
    if where:
        args.extend(["--where", where])
    if limit:
        args.extend(["--limit", str(limit)])
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_get_banner(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Retrieve database banner information"""
    args = ["-u", url, "--banner"]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_get_current_user(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Retrieve current database user"""
    args = ["-u", url, "--current-user"]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_get_current_db(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Retrieve current database name"""
    args = ["-u", url, "--current-db"]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_read_file(
    url: str,
    file_path: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Read a file from the database server file system"""
    args = ["-u", url, "--file-read", file_path]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_execute_command(
    url: str,
    command: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None
) -> str:
    """Execute an operating system command on the database server"""
    args = ["-u", url, "--os-cmd", command]
    
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


@app.tool()
async def sqlmap_advanced_scan(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    tor: bool = False,
    random_agent: bool = False,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    dbms: Optional[str] = None,
    timeout: int = 30,
    threads: int = 1
) -> str:
    """Perform advanced SQLMap scan with custom options"""
    args = ["-u", url]
    
    # Add all available options
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    if user_agent:
        args.extend(["--user-agent", user_agent])
    if proxy:
        args.extend(["--proxy", proxy])
    if tor:
        args.append("--tor")
    if random_agent:
        args.append("--random-agent")
    if level:
        args.extend(["--level", str(level)])
    if risk:
        args.extend(["--risk", str(risk)])
    if technique:
        args.extend(["--technique", technique])
    if dbms:
        args.extend(["--dbms", dbms])
    if timeout:
        args.extend(["--timeout", str(timeout)])
    if threads:
        args.extend(["--threads", str(threads)])
    
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"


if __name__ == "__main__":
    # Run the FastMCP server
    logger.info("Starting SQLMap MCP server")
    try:
        app.run()
    except Exception as e:
        logger.error(f"Failed to start MCP server: {str(e)}")
        sys.exit(1)
