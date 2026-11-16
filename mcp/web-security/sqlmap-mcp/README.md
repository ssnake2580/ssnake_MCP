# SQLMap MCP Server (FastMCP)

A Model Context Protocol (MCP) server built with FastMCP that exposes SQLMap CLI tools as MCP functions for automated SQL injection testing and database reconnaissance.

## Overview

This MCP server provides programmatic access to SQLMap's powerful SQL injection testing capabilities through a standardized interface. Built with FastMCP for simplicity and ease of use, it allows AI assistants and other MCP clients to perform automated security testing, database enumeration, and vulnerability assessment.

## Features

### Core SQLMap Capabilities Exposed

1. **Basic Scanning**
   - URL-based SQL injection detection
   - Configurable test levels and risk assessment
   - Multiple injection technique support

2. **Database Enumeration**
   - Database discovery and listing
   - Table enumeration within databases
   - Column enumeration within tables
   - Schema analysis

3. **Data Retrieval**
   - Table data dumping with filtering options
   - Selective column extraction
   - WHERE clause support for targeted queries

4. **System Information**
   - Database banner retrieval
   - Current user identification
   - Current database detection
   - Hostname enumeration

5. **Advanced Access**
   - File system access (read files from database server)
   - Operating system command execution
   - Custom payload injection

6. **Advanced Options**
   - Proxy support
   - Tor network integration
   - Custom User-Agent configuration
   - Multi-threading support
   - Request timeout configuration

## Installation

### Prerequisites

1. **Python 3.13+** (as specified in pyproject.toml)
2. **FastMCP** - Automatically installed via dependencies
3. **SQLMap** - Install via your preferred method:
   ```bash
   # Using Homebrew (macOS)
   brew install sqlmap
   
   # Using pip
   pip install sqlmap
   
   # Or clone from GitHub
   git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
   ```

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd sqlmap-mcp
   ```

2. **Install dependencies:**
   ```bash
   # Using uv (recommended)
   uv sync
   
   # Or using pip
   pip install -e .
   ```

3. **Verify SQLMap installation:**
   ```bash
   sqlmap --version
   ```

## Usage

### Running the Server

```bash
python server.py
```

### MCP Client Configuration

Add this server to your MCP client configuration:

```json
{
  "mcpServers": {
    "sqlmap": {
      "command": "python",
      "args": ["/path/to/sqlmap-mcp/server.py"],
      "env": {}
    }
  }
}
```

### Available Tools

#### 1. `sqlmap_help`
Show SQLMap help information.
- **Parameters:**
  - `advanced` (boolean): Show advanced help (use -hh)

#### 2. `sqlmap_scan_url`
Scan a target URL for SQL injection vulnerabilities.
- **Required Parameters:**
  - `url` (string): Target URL to scan
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value
  - `level` (integer, 1-5): Level of tests to perform
  - `risk` (integer, 1-3): Risk of tests to perform
  - `technique` (string): SQL injection techniques to use

#### 3. `sqlmap_enumerate_databases`
Enumerate databases on the target.
- **Required Parameters:**
  - `url` (string): Target URL
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 4. `sqlmap_enumerate_tables`
Enumerate tables in a specific database.
- **Required Parameters:**
  - `url` (string): Target URL
  - `database` (string): Database name to enumerate
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 5. `sqlmap_enumerate_columns`
Enumerate columns in a specific table.
- **Required Parameters:**
  - `url` (string): Target URL
  - `database` (string): Database name
  - `table` (string): Table name to enumerate
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 6. `sqlmap_dump_table`
Dump data from a specific table.
- **Required Parameters:**
  - `url` (string): Target URL
  - `database` (string): Database name
  - `table` (string): Table name to dump
- **Optional Parameters:**
  - `columns` (string): Specific columns to dump (comma-separated)
  - `where` (string): WHERE clause to limit results
  - `limit` (integer): Limit number of rows to dump
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 7. `sqlmap_get_banner`
Retrieve database banner information.
- **Required Parameters:**
  - `url` (string): Target URL
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 8. `sqlmap_get_current_user`
Retrieve current database user.
- **Required Parameters:**
  - `url` (string): Target URL
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 9. `sqlmap_get_current_db`
Retrieve current database name.
- **Required Parameters:**
  - `url` (string): Target URL
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 10. `sqlmap_read_file`
Read a file from the database server file system.
- **Required Parameters:**
  - `url` (string): Target URL
  - `file_path` (string): Path to the file to read
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 11. `sqlmap_execute_command`
Execute an operating system command on the database server.
- **Required Parameters:**
  - `url` (string): Target URL
  - `command` (string): OS command to execute
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value

#### 12. `sqlmap_advanced_scan`
Perform advanced SQLMap scan with custom options.
- **Required Parameters:**
  - `url` (string): Target URL
- **Optional Parameters:**
  - `data` (string): POST data string
  - `cookie` (string): HTTP Cookie header value
  - `user_agent` (string): Custom User-Agent header
  - `proxy` (string): Proxy to use
  - `tor` (boolean): Use Tor anonymity network
  - `random_agent` (boolean): Use random User-Agent
  - `level` (integer, 1-5): Level of tests
  - `risk` (integer, 1-3): Risk of tests
  - `technique` (string): SQL injection techniques
  - `dbms` (string): Force back-end DBMS
  - `timeout` (integer): Request timeout in seconds
  - `threads` (integer, 1-10): Number of concurrent threads

## Example Usage

### Basic URL Scan
```json
{
  "name": "sqlmap_scan_url",
  "arguments": {
    "url": "http://example.com/vuln.php?id=1",
    "level": 2,
    "risk": 2
  }
}
```

### Database Enumeration
```json
{
  "name": "sqlmap_enumerate_databases",
  "arguments": {
    "url": "http://example.com/vuln.php?id=1"
  }
}
```

### Advanced Scan with Proxy
```json
{
  "name": "sqlmap_advanced_scan",
  "arguments": {
    "url": "http://example.com/vuln.php?id=1",
    "proxy": "http://127.0.0.1:8080",
    "level": 3,
    "risk": 2,
    "threads": 5,
    "random_agent": true
  }
}
```

## Security Considerations

### ⚠️ Important Security Warnings

1. **Legal Compliance**: Only use this tool on systems you own or have explicit permission to test.

2. **Authorization**: Ensure you have proper authorization before performing any security testing.

3. **Environment Isolation**: Use in isolated testing environments to prevent unintended access to production systems.

4. **Data Protection**: Be aware that SQLMap can extract sensitive data from databases.

5. **Rate Limiting**: Implement appropriate rate limiting to avoid overwhelming target systems.

6. **Logging**: Monitor and log all activities for audit purposes.

### Best Practices

1. **Test Environment**: Always test in a controlled, isolated environment first.

2. **Documentation**: Document all testing activities and results.

3. **Responsible Disclosure**: If vulnerabilities are found, follow responsible disclosure practices.

4. **Access Control**: Restrict access to this MCP server to authorized personnel only.

5. **Monitoring**: Implement monitoring to detect unauthorized usage.

## Development

### Project Structure
```
sqlmap-mcp/
├── server.py          # Main FastMCP server implementation
├── pyproject.toml     # Project configuration and dependencies
├── README.md          # This file
└── .gitignore         # Git ignore rules
```

### Adding New Tools

To add new SQLMap functionality with FastMCP:

1. Add a new function decorated with `@app.tool()`
2. Define the function parameters with proper type hints
3. Add a docstring describing the tool's purpose
4. Implement the SQLMap command execution logic

Example:
```python
@app.tool()
async def my_new_tool(url: str, param: Optional[str] = None) -> str:
    """Description of what this tool does"""
    args = ["-u", url]
    if param:
        args.extend(["--param", param])
    result = await sqlmap_executor.execute_sqlmap(args)
    return result.output if result.success else f"Error: {result.error}"
```

### Testing

```bash
# Test the server
python server.py

# Test with a simple MCP client
# (Use your preferred MCP client to test the tools)
```

## Troubleshooting

### Common Issues

1. **SQLMap not found**: Ensure SQLMap is installed and accessible in your PATH
2. **Permission denied**: Check file permissions and ensure proper access rights
3. **Timeout errors**: Increase timeout values for complex scans
4. **Connection issues**: Verify network connectivity and proxy settings

### Debug Mode

Enable debug logging by modifying the server configuration or adding logging statements.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the same license as SQLMap (GPLv2). See the LICENSE file for details.

## Acknowledgments

- [SQLMap Project](https://github.com/sqlmapproject/sqlmap) - The underlying SQL injection testing tool
- [FastMCP](https://github.com/jlowin/fastmcp) - The simplified MCP framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification and implementation

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review SQLMap documentation
3. Open an issue on the project repository

---

**Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any system.
