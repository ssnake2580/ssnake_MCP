[中文](README_CN.md)

# MCP for Security - Python Version

This is a Python refactored version of the security tools MCP (Model Context Protocol) server collection, implemented using the FastMCP library.

## 🌟 Project Origin & Declaration

### Acknowledgment to Original Author
This project is a complete Python refactoring based on **[cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security)** JavaScript/TypeScript version. We thank **cyproxio** for open-sourcing this excellent security tools MCP server collection, which provides important contributions to the standardization of cybersecurity tools.

### Refactoring Notes
⚠️ **Important Declaration:**
- This project was **completely refactored by Claude 4 AI**, converting from JavaScript/TypeScript to Python
- **Has NOT been verified through manual real-machine testing**, may contain runtime errors or functional defects
- Code logic is based on translation and adaptation from the original version, but may contain understanding bias
- **Please analyze the code yourself**, use cautiously in production environments
- If issues are found, **welcome to submit PRs** or Issues to help improve the project

## 🎯 Project Goals

Complete refactoring of 20 JavaScript version security tool MCP servers to Python version, maintaining:
- ✅ 100% API compatibility (theoretically)
- ✅ Same functionality and parameters
- ✅ Independent operation with no interdependencies
- ✅ Detailed Chinese documentation

## 📁 Project Structure

```
mcp-for-security-python/
├── README.md                    # This file
├── sqlmap-mcp/                  # SQL injection testing tool
├── assetfinder-mcp/             # Subdomain discovery tool
├── waybackurls-mcp/             # Historical URL discovery tool
├── crtsh-mcp/                   # SSL certificate log query tool
├── shuffledns-mcp/              # DNS brute force tool
├── httpx-mcp/                   # HTTP service detection tool
├── ffuf-mcp/                    # Web fuzzing tool
├── nuclei-mcp/                  # Vulnerability scanning tool
├── nmap-mcp/                    # Network scanning tool
├── masscan-mcp/                 # High-speed port scanning tool
├── alterx-mcp/                  # Domain mutation generation tool
├── arjun-mcp/                   # HTTP parameter discovery tool
├── katana-mcp/                  # Web crawler tool
├── sslscan-mcp/                 # SSL/TLS security scanning tool
├── http-headers-security-mcp/   # HTTP header security check tool
├── mobsf-mcp/                   # Mobile app security analysis tool
├── scoutsuite-mcp/              # Cloud security audit tool
├── smuggler-mcp/                # HTTP request smuggling vulnerability detection
├── amass-mcp/                   # Asset discovery and reconnaissance tool
└── wpsscan-mcp/                 # WordPress security scanning tool
```

## 🚀 MCP Server List

### ✅ Completed (20/20 - 100%)

#### Basic Tools
1. **assetfinder-mcp** - Subdomain discovery tool
   - Function: Quickly discover subdomains of target domains
   - Feature: Automatic ANSI color code cleaning

2. **waybackurls-mcp** - Historical URL discovery tool
   - Function: Retrieve historical URLs from Wayback Machine
   - Feature: Support include/exclude subdomain options

3. **crtsh-mcp** - SSL certificate log query tool
   - Function: Discover subdomains from certificate transparency logs
   - Feature: API calls, no local tools required

4. **shuffledns-mcp** - DNS brute force tool
   - Function: Efficient DNS resolution and brute forcing
   - Feature: Integrated massdns, supports multiple modes

5. **alterx-mcp** - Domain mutation generation tool
   - Function: Generate domain mutations for subdomain discovery
   - Feature: Support multiple mutation modes and custom templates

#### Scanning Tools
6. **httpx-mcp** - HTTP service detection tool
   - Function: Fast HTTP/HTTPS service discovery
   - Feature: Rich detection options and concurrent processing

7. **nmap-mcp** - Network scanning tool
   - Function: Comprehensive network discovery and port scanning
   - Feature: Complete nmap parameter support

8. **masscan-mcp** - High-speed port scanning tool
   - Function: High-speed large-scale port scanning
   - Feature: Support custom rates and port ranges

9. **nuclei-mcp** - Vulnerability scanning tool
   - Function: Template-based vulnerability scanning
   - Feature: Multiple tool functions, including tag retrieval API

10. **sslscan-mcp** - SSL/TLS security scanning tool
    - Function: SSL/TLS configuration and vulnerability detection
    - Feature: Support multiple SSL/TLS testing options

#### Fuzzing Tools
11. **ffuf-mcp** - Web fuzzing tool
    - Function: High-performance web directory and parameter fuzzing
    - Feature: Complete parameter configuration support

12. **arjun-mcp** - HTTP parameter discovery tool
    - Function: Discover hidden HTTP GET/POST parameters
    - Feature: Support multiple detection modes and custom dictionaries

#### Web Crawler
13. **katana-mcp** - Web crawler tool
    - Function: Fast web crawling and endpoint discovery
    - Feature: Support JavaScript rendering and deep crawling

#### Vulnerability Testing
14. **sqlmap-mcp** - SQL injection testing tool
    - Function: Automated SQL injection detection and exploitation
    - Feature: Support rich parameter configurations

15. **smuggler-mcp** - HTTP request smuggling vulnerability detection
    - Function: Detect HTTP Request Smuggling vulnerabilities
    - Feature: Support CL.TE and TE.CL type detection

16. **wpsscan-mcp** - WordPress security scanning tool
    - Function: WordPress website security vulnerability scanning
    - Feature: Support plugin, theme, user enumeration, etc.

#### Security Audit
17. **http-headers-security-mcp** - HTTP header security check tool
    - Function: Analyze security configuration of HTTP response headers
    - Feature: Security assessment based on OWASP standards

18. **mobsf-mcp** - Mobile app security analysis tool
    - Function: Android/iOS mobile app security analysis
    - Feature: API integration, support static and dynamic analysis

19. **scoutsuite-mcp** - Cloud security audit tool
    - Function: Multi-cloud platform security configuration audit
    - Feature: Support AWS, Azure, GCP and other cloud platforms

20. **amass-mcp** - Network asset discovery tool
    - Function: Comprehensive network asset discovery and reconnaissance
    - Feature: Support multiple data sources and deep reconnaissance

## 🛠️ Technical Features

### Unified Architecture
- **Framework**: FastMCP 2.0+
- **Language**: Python 3.8+
- **Async Processing**: asyncio
- **Type Annotations**: typing module

### Core Functions
- **Tool Functions**: `@mcp.tool()` decorator
- **Async Execution**: subprocess + asyncio
- **Error Handling**: Unified exception capture and return
- **Documentation Support**: Complete docstring and parameter descriptions

### Implementation Patterns

#### 1. Command Line Tool Wrapper (Most tools)
```python
@mcp.tool()
async def tool_name(target: str, args: List[str] = None) -> str:
    cmd = [tool_command] + construct_args(target, args)
    process = await asyncio.create_subprocess_exec(...)
    stdout, _ = await process.communicate()
    return process_output(stdout)
```

#### 2. API Call Integration (crtsh-mcp, mobsf-mcp, etc.)
```python
@mcp.tool()
async def api_tool(target: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(api_url) as response:
            data = await response.json()
            return process_api_data(data)
```

#### 3. Multiple Tool Functions (nuclei-mcp, etc.)
```python
@mcp.tool()
async def primary_function(...) -> str:
    # Main functionality

@mcp.tool()
async def helper_function(...) -> str:
    # Helper functionality (like getting configs, tags, etc.)
```

## 📦 Installation and Usage

### Environment Requirements
```bash
# Python environment
python >= 3.8

# Install FastMCP
pip install fastmcp>=2.0.0

# Install additional dependencies as needed
pip install aiohttp>=3.8.0  # For API-based tools
```

### General Usage Process

1. **Enter tool directory**
```bash
cd mcp-for-security-python/[tool-name]-mcp/
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Start server**
```bash
# For command line tools (most)
python server.py [tool-binary-path]

# For API tools (like mobsf-mcp)
python server.py [api-base-url] [api-key]

# For script tools (like smuggler-mcp)
python server.py [python-path] [script-path]
```

4. **Configure MCP client**
```json
{
  "mcpServers": {
    "tool-name-mcp": {
      "command": "python",
      "args": ["/path/to/tool-mcp/server.py", "tool-binary"]
    }
  }
}
```

## 🔧 Development Guide

### Refactoring Standards
1. **API Compatibility**: Maintain exactly the same interface as JavaScript version
2. **Function Description**: Directly use original docstring content
3. **Parameter Handling**: Support same parameter types and structures
4. **Error Handling**: Unified exception handling and return formats
5. **Documentation Completeness**: Each tool has detailed README.md

### Code Template
```python
#!/usr/bin/env python3
"""
Tool MCP Server
Description of the tool functionality.
"""

import sys
import asyncio
from typing import List, Optional
from mcp.server.fastmcp import FastMCP

# Command line argument handling
if len(sys.argv) < 2:
    print("Usage: python server.py <tool-binary>", file=sys.stderr)
    sys.exit(1)

tool_command = sys.argv[1]
mcp = FastMCP("tool-name", version="1.0.0")

@mcp.tool()
async def tool_function(param: str, optional_param: Optional[List[str]] = None) -> str:
    """Tool function description"""
    # Implementation
    pass

if __name__ == "__main__":
    mcp.run()
```

## 🐛 Known Issues & Limitations

### Potential Issues
- **Not real-machine tested**: All code is AI-refactored, not verified through actual execution
- **Dependency compatibility**: May have Python library version compatibility issues
- **Parameter parsing**: Command line parameter construction may contain errors
- **Exception handling**: Error handling logic may not be comprehensive enough
- **Performance optimization**: Not optimized for Python-specific features

### How to Contribute
We welcome community contributions to improve this project:

1. **Testing verification**: Test tool functionality in actual environments
2. **Issue reporting**: Report discovered issues through GitHub Issues
3. **Code fixes**: Submit PRs to fix discovered errors
4. **Feature improvements**: Optimize performance or add new features
5. **Documentation improvement**: Improve documentation and usage examples

## 🛡️ Security Reminders

⚠️ **Important Security Warning**

These tools are only for legitimate security testing and research purposes:

1. **Authorized use**: Only use on systems you own or have explicit authorization to test
2. **Legal compliance**: Comply with all applicable laws and regulations
3. **Responsible disclosure**: Vulnerabilities found should be disclosed responsibly
4. **Ethical use**: Aim to improve security, not for malicious attacks
5. **Testing verification**: Due to lack of real-machine testing, please verify functionality in secure environments first

## 📄 License

This project is released under the MIT license.

The original project [cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security) is also under MIT license.

## 🤝 Contributing

Welcome to contribute code to improve the project:

1. Fork the project
2. Create a feature branch
3. Test your changes
4. Submit a Pull Request

Especially welcome:
- Real-machine testing feedback
- Bug fixes
- Performance optimizations
- Documentation improvements

## 📞 Contact

For questions or suggestions, please contact through GitHub Issues.

## 🙏 Acknowledgments

- Thanks to **[cyproxio](https://github.com/cyproxio)** for open-sourcing the original JavaScript MCP server collection
- Thanks to all security tool original authors for providing these excellent security tools
- Thanks to MCP protocol and FastMCP library developers

---

**MCP for Security - Python Version** | Making security tools more accessible and powerful 🚀