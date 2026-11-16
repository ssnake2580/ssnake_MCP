# WPScan MCP Server

A Model Context Protocol (MCP) server that provides WPScan functionality for WordPress security scanning.

## Description

This MCP server wraps the WPScan tool, allowing you to perform comprehensive security audits of WordPress websites through the MCP protocol. WPScan is a black box WordPress vulnerability scanner that can identify:

- WordPress version vulnerabilities
- Plugin vulnerabilities  
- Theme vulnerabilities
- Configuration issues
- Weak passwords
- Exposed files and directories

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure WPScan is installed on your system:
```bash
# Install WPScan (Ruby required)
gem install wpscan

# Or using package manager on Ubuntu/Debian
sudo apt update
sudo apt install wpscan

# Or using Homebrew on macOS
brew install wpscan
```

## Usage

Run the server with the WPScan binary path:

```bash
python server.py /usr/local/bin/wpscan
```

Or if wpscan is in your PATH:
```bash
python server.py wpscan
```

## Available Tools

### do-wpscan

Runs WPScan to analyze WordPress websites.

**Parameters:**

- `url` (required): Target WordPress website URL (must start with http:// or https://)
- `detection_mode` (optional): Scan detection mode
  - `"mixed"` (default): Combines passive and aggressive scanning
  - `"passive"`: Non-intrusive scanning only
  - `"aggressive"`: Thorough but potentially detectable scanning
- `random_user_agent` (optional): Enable random user agent rotation
- `max_threads` (optional): Maximum concurrent scanning threads (default: 5)
- `disable_tls_checks` (optional): Disable SSL/TLS certificate verification
- `proxy` (optional): Proxy server (format: protocol://IP:port)
- `cookies` (optional): Custom cookies (format: name1=value1; name2=value2)
- `force` (optional): Skip WordPress detection and 403 response checks
- `enumerate` (optional): List of enumeration options:
  - `"vp"`: Scan for vulnerable plugins
  - `"ap"`: Scan all installed plugins  
  - `"p"`: Scan only popular plugins
  - `"vt"`: Scan for vulnerable themes
  - `"at"`: Scan all installed themes
  - `"t"`: Scan only popular themes
  - `"tt"`: Scan for timthumb vulnerabilities
  - `"cb"`: Scan for configuration backups
  - `"dbe"`: Scan for database exports

**Example:**
```json
{
  "url": "https://example.com",
  "detection_mode": "mixed",
  "enumerate": ["vp", "vt", "cb"]
}
```

## Notes

- Some enumeration options are mutually exclusive:
  - Only one of `vp`, `ap`, `p` can be used
  - Only one of `vt`, `at`, `t` can be used
- Default enumeration if not specified: `vp,vt,tt,cb,dbe,u,m`
- Higher thread counts may trigger rate limiting on target websites
- Use proxy settings when scanning through corporate firewalls or for anonymity
- The `force` option should be used when you're certain the target is WordPress but detection fails

## Requirements

- Python 3.7+
- FastMCP 2.0.0+
- WPScan (Ruby gem or system package)

## Security Considerations

- Only scan websites you own or have explicit permission to test
- Be aware that aggressive scanning may trigger security alerts
- Consider using proxy settings in sensitive environments
- Some scans may be logged by target websites 