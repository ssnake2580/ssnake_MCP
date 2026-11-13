# Forensics Utils MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A comprehensive MCP Server for forensic analysis that enables AI agents to analyze files, Chromium browser artifacts, and Firefox browser artifacts through the Model Context Protocol. Integrates with VirusTotal API, Detect It Easy (DIE), Binwalk, deep Chromium parsing, Firefox artifact parsing, and local analysis tools.

## Features

- **VirusTotal Integration**: Full API v3 support with file, URL, domain, and IP analysis
- **Local Analysis**: Hash calculation, string extraction, EXIF metadata, DIE analysis
- **Firefox Artifacts**: History, bookmarks, download candidates, cookies, sessions, session storage, favicons, extensions, preferences, web data, login metadata, local storage, IndexedDB, cache, and login decryption
- **Chromium Artifacts**: History, downloads, sessions, favicons, bookmarks, saved logins, cookies, Web Data, extensions, preferences, Local Storage, Session Storage, IndexedDB, and HTTP cache parsing
- **Firmware Analysis**: Binwalk integration for embedded file extraction
- **Intelligent Caching**: In-memory cache with 200MB limit for optimal performance
- **Rate Limiting**: Automatic queue management for VirusTotal API (4 req/min)
- **Multi-Format Support**: EXE, ELF, firmware images, disk images, and more
- **Security First**: API key protection via environment variables

## Requirements

- Python 3.10+
- VirusTotal API key (optional, for VT features)
- External tools: DIE, ExifTool, Binwalk (optional, for local analysis)
- MCP-compatible client (Claude Desktop, VSCode, Cline, etc.)

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/jus1-c/forensics-utils-mcp-server.git
cd forensics-utils-mcp-server
```

### 2. Create Virtual Environment

```bash
# Linux/Mac
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Package

```bash
pip install -e ".[dev]"
```

This installs `ccl_chromium_reader`, `lz4`, and `firefox_decrypt` by default so the Chromium and Firefox browser-artifact tools are available without extra setup.

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required for VirusTotal features
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional
CACHE_MAX_SIZE_MB=200
```

Get your VirusTotal API key from: https://www.virustotal.com/gui/my-apikey

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "forensics-utils": {
      "command": "python",
      "args": ["-m", "forensics_utils_mcp_server"],
      "cwd": "/path/to/forensics-utils-mcp-server",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Note:** Change `cwd` to your actual project directory path.

### VSCode (with Cline extension)

Add to your settings:

```json
{
  "mcpServers": {
    "forensics-utils": {
      "command": "python",
      "args": ["-m", "forensics_utils_mcp_server"],
      "cwd": "/path/to/forensics-utils-mcp-server",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Note:** Change `cwd` to your actual project directory path.

### OpenCode

Add to `~/.opencode/opencode.json`:

```json
{
  "mcp": {
    "forensics-utils": {
      "type": "local",
      "command": ["python", "-m", "forensics_utils_mcp_server"],
      "cwd": "/path/to/forensics-utils-mcp-server",
      "enabled": true,
      "timeout": 60000
    }
  }
}
```

**Note:** Change `cwd` to your actual project directory path.

## External Dependencies

### Detect It Easy (DIE)
Required for `die_analyze_file` tool.
- Download: https://github.com/horsicq/Detect-It-Easy/releases
- Add `diec` to PATH

### ExifTool
Required for `extract_exif` tool.
- Windows: https://exiftool.org/install.html
- Linux: `sudo apt-get install libimage-exiftool-perl`
- macOS: `brew install exiftool`

### Binwalk
Required for `binwalk_scan` and `binwalk_extract` tools.
```bash
pip install binwalk
```

## Available Tools

### Typical browser profile paths

The browser-artifact tools (`chromium_*` / `firefox_*`) operate on a **profile
directory that already exists on the local filesystem**. The MCP does not
mount disk images — pair it with a disk-extraction MCP such as `disk-forensics`
to pull a profile out of a forensic image first.

Typical locations inside a Windows image:

| Browser | Path (inside the user profile) |
| --- | --- |
| Google Chrome | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default` |
| Microsoft Edge | `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default` |
| Mozilla Firefox | `C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<rand>.default-release` |

Suggested workflow with `disk-forensics`:

1. `extract_directory(image_path, partition_offset, directory_path=<above>, output_path=/tmp/opencode/case-A/chrome)` to pull the profile onto disk.
2. Pass the host path (e.g. `/tmp/opencode/case-A/chrome/Default`) as `profile_path` to any `chromium_*` / `firefox_*` tool.

`Local State` (Chromium v10/v11 decryption) lives one level up at
`C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State` —
extract it alongside the profile and pass via `local_state_path`.

### Firefox Artifacts

#### firefox_profile_summary_tool
Summarize basic Firefox artifacts present in a profile.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `sample_limit`: Maximum number of sample identifiers per artifact (default: 10)

#### firefox_parse_history_tool
Parse Firefox browsing history records.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `url`: Optional exact URL filter
- `title`: Optional exact page title filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_bookmarks_tool
Parse Firefox bookmark entries.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `url`: Optional exact bookmark URL filter
- `title`: Optional exact bookmark title filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_downloads_tool
Parse Firefox download candidates reconstructed from `places.sqlite`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `download_url`: Optional exact downloaded file URL filter
- `source_url`: Optional exact referring/source URL filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_cookies_tool
Parse Firefox cookies from `cookies.sqlite`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `host`: Optional exact cookie host filter
- `name`: Optional exact cookie name filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_sessions_tool
Parse Firefox session restore entries from `sessionstore.jsonlz4` and `sessionstore-backups/*.jsonlz4`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `file_name`: Optional exact session file name filter
- `url`: Optional exact URL filter
- `title`: Optional exact page title filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_session_storage_tool
Parse Firefox session storage records when sessionstore contains them.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `host`: Optional exact session storage host/origin filter
- `key`: Optional exact session storage key filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_favicons_tool
Parse Firefox favicon mappings and optional favicon image previews.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `page_url`: Optional exact page URL filter
- `icon_url`: Optional exact favicon URL filter
- `limit`: Maximum records to return (default: 100)
- `include_image`: Include favicon image previews as base64 (default: false)
- `max_image_bytes`: Maximum bytes per favicon preview (default: 4096)

#### firefox_parse_extensions_tool
Parse Firefox installed extension metadata from `extensions.json`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `extension_id`: Optional exact extension ID filter
- `name`: Optional exact extension name filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_preferences_tool
Parse Firefox preferences from `prefs.js`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `key_path`: Optional exact preference key filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_logins_tool
Parse Firefox saved-login metadata from `logins.json` without decrypting passwords.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `hostname`: Optional exact hostname filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_web_data_tool
Parse Firefox web-data-like artifacts such as form history, permissions, content preferences, and search engines.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `category`: Optional exact category filter (`form_history`, `permissions`, `content_prefs`, `search_engines`)
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_local_storage_tool
Parse Firefox local storage records from `webappsstore.sqlite` and `storage/default/*/ls/data.sqlite`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `origin_key`: Optional exact origin/storage key filter
- `key`: Optional exact local storage key filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_indexeddb_tool
Parse Firefox IndexedDB records from `storage/default/*/idb`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `host_id`: Optional exact storage/default origin directory filter
- `database_name`: Optional exact IndexedDB database name filter
- `object_store_name`: Optional exact object store filter
- `limit`: Maximum records to return (default: 100)

#### firefox_parse_cache_tool
Parse Firefox cache records from `storage/default/*/cache`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `url`: Optional exact request URL filter
- `limit`: Maximum records to return (default: 100)
- `include_body`: Include cached body previews when the morgue file is present (default: false)
- `max_body_bytes`: Maximum bytes per body preview (default: 16384)

#### firefox_decrypt_cookies_tool
Return Firefox cookies as already-decrypted plaintext values.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `host`: Optional exact cookie host filter
- `name`: Optional exact cookie name filter
- `limit`: Maximum records to return (default: 100)

#### firefox_decrypt_logins_tool
Attempt to decrypt Firefox saved passwords via `firefox_decrypt`.

**Parameters:**
- `profile_path`: Absolute path to Firefox profile directory (required)
- `primary_password`: Optional primary password. Leave empty or unset if none is configured
- `hostname`: Optional exact hostname filter
- `limit`: Maximum records to return (default: 100)
- `nss_lib_path`: Optional path to an NSS library directory for `firefox_decrypt`

**Notes:**
- Decryption depends on NSS being available in the active environment
- If the profile is protected by a primary password, you must provide it explicitly

### Chromium Deep Artifacts

#### chromium_profile_summary_tool
Summarize deep Chromium artifacts present in a profile.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `sample_limit`: Maximum number of sample identifiers per artifact (default: 10)

#### chromium_parse_local_storage_tool
Parse Chromium Local Storage records.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `storage_key`: Optional exact origin/storage key filter
- `script_key`: Optional exact Local Storage key filter
- `limit`: Maximum records to return (default: 100)
- `include_deletions`: Include recovered deletion records when available (default: false)

#### chromium_parse_session_storage_tool
Parse Chromium Session Storage records.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `host`: Optional exact host filter
- `key`: Optional exact Session Storage key filter
- `limit`: Maximum records to return (default: 100)
- `include_deletions`: Include recovered deletion records when available (default: false)

#### chromium_parse_indexeddb_tool
Parse Chromium IndexedDB records.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `host_id`: Optional exact IndexedDB host/origin folder filter
- `database_name`: Optional exact database name filter
- `object_store_name`: Optional exact object store filter
- `limit`: Maximum records to return (default: 100)
- `include_deletions`: Include deleted/non-live records when available (default: false)

#### chromium_parse_cache_tool
Parse Chromium HTTP cache metadata and optional cached body previews.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `url`: Optional exact URL filter
- `limit`: Maximum records to return (default: 100)
- `include_body`: Include cached response body previews (default: false)
- `max_body_bytes`: Maximum bytes per cached body preview (default: 16384)
- `decompress`: Decompress gzip/brotli/deflate responses when possible (default: true)

#### chromium_parse_history_tool
Parse Chromium browsing history records.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `url`: Optional exact URL filter
- `title`: Optional exact page title filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_downloads_tool
Parse Chromium download records from `History` and `shared_proto_db` when present.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `download_url`: Optional exact downloaded URL filter
- `tab_url`: Optional exact originating tab URL filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_sessions_tool
Parse Chromium session restore navigation entries from `Sessions/`, `Current Session`, `Last Session`, `Current Tabs`, and `Last Tabs` when present.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `file_name`: Optional exact session file name filter
- `url`: Optional exact URL filter
- `title`: Optional exact page title filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_favicons_tool
Parse Chromium favicon mappings and bitmap metadata from the `Favicons` database.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `page_url`: Optional exact page URL filter
- `icon_url`: Optional exact favicon URL filter
- `limit`: Maximum records to return (default: 100)
- `include_image`: Include favicon image previews as base64 (default: false)
- `max_image_bytes`: Maximum bytes per favicon preview (default: 4096)

#### chromium_parse_web_data_tool
Parse common Chromium `Web Data` tables such as autofill, keywords, and profiles.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `category`: Optional exact category filter (`autofill`, `keywords`, `profiles`)
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_extensions_tool
Parse Chromium installed extension metadata from `Extensions/` and merge available state from Preferences.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `extension_id`: Optional exact extension ID filter
- `name`: Optional exact extension name filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_preferences_tool
Parse selected Chromium `Preferences` and `Secure Preferences` values.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `key_path`: Optional dot-separated preference path filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_bookmarks_tool
Parse Chromium bookmark URL entries from the `Bookmarks` JSON file.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `url`: Optional exact bookmark URL filter
- `title`: Optional exact bookmark title filter
- `limit`: Maximum records to return (default: 100)

#### chromium_parse_logins_tool
Parse Chromium saved-login metadata from the `Login Data` SQLite database without decrypting passwords.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `origin_url`: Optional exact origin URL filter
- `username_value`: Optional exact username filter
- `limit`: Maximum records to return (default: 100)

#### chromium_decrypt_logins_tool
Attempt to decrypt Chromium saved passwords.

Supports two modes:
- Windows current-user context using `Local State` + DPAPI
- Offline/manual mode when a decrypted Chromium master key is supplied via `master_key_b64`

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `local_state_path`: Optional path to the Chromium `Local State` file
- `master_key_b64`: Optional decrypted Chromium master key in base64 form
- `origin_url`: Optional exact origin URL filter
- `username_value`: Optional exact username filter
- `limit`: Maximum records to return (default: 100)

**Notes:**
- `v10`/`v11` password blobs require the Chromium master key
- Older DPAPI-only blobs require Windows DPAPI in the current user context
- App-bound `v20` encryption is not currently supported

#### chromium_parse_cookies_tool
Parse Chromium cookies from either legacy `Cookies` or modern `Network/Cookies` SQLite databases.

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `host_key`: Optional exact cookie domain filter
- `name`: Optional exact cookie name filter
- `limit`: Maximum records to return (default: 100)

#### chromium_decrypt_cookies_tool
Attempt to decrypt Chromium cookies.

Supports two modes:
- Windows current-user context using `Local State` + DPAPI
- Offline/manual mode when a decrypted Chromium master key is supplied via `master_key_b64`

**Parameters:**
- `profile_path`: Absolute path to Chromium profile directory (required)
- `local_state_path`: Optional path to the Chromium `Local State` file
- `master_key_b64`: Optional decrypted Chromium master key in base64 form
- `host_key`: Optional exact cookie domain filter
- `name`: Optional exact cookie name filter
- `limit`: Maximum records to return (default: 100)

**Notes:**
- Plaintext cookie values are returned directly when no encrypted blob is present
- `v10`/`v11` cookie blobs require the Chromium master key
- Older DPAPI-only blobs require Windows DPAPI in the current user context
- App-bound `v20` encryption is not currently supported

### VirusTotal File Analysis

#### 1. vt_scan_file
Upload a file to VirusTotal for scanning or check by hash.

**Parameters:**
- `file_path`: Absolute path to file (required)

**Example:**
```json
{
  "file_path": "/home/user/samples/suspicious.exe"
}
```

#### 2. vt_get_file_report
Get VirusTotal analysis report for a file by its hash.

**Parameters:**
- `file_hash`: MD5, SHA1, or SHA256 hash (required)

**Example:**
```json
{
  "file_hash": "d41d8cd98f00b204e9800998ecf8427e"
}
```

#### 3. vt_get_file_behavior
Get sandbox behavior analysis for a file.

**Parameters:**
- `file_hash`: SHA256 hash (required)

**Example:**
```json
{
  "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### VirusTotal URL Analysis

#### 4. vt_scan_url
Submit a URL to VirusTotal for scanning.

**Parameters:**
- `url`: URL to scan (required)

**Example:**
```json
{
  "url": "http://example.com"
}
```

#### 5. vt_get_url_report
Get VirusTotal analysis report for a URL.

**Parameters:**
- `url`: URL to analyze (required)

**Example:**
```json
{
  "url": "http://example.com"
}
```

### VirusTotal Domain/IP Intelligence

#### 6. vt_get_domain_report
Get VirusTotal intelligence report for a domain.

**Parameters:**
- `domain`: Domain name (required)

**Example:**
```json
{
  "domain": "example.com"
}
```

#### 7. vt_get_ip_report
Get VirusTotal intelligence report for an IP address.

**Parameters:**
- `ip`: IP address (required)

**Example:**
```json
{
  "ip": "8.8.8.8"
}
```

### VirusTotal Search

#### 8. vt_search_files
Search for files using VirusTotal Intelligence.

**Parameters:**
- `query`: Search query string (required)
- `limit`: Maximum results (default: 10)

**Example:**
```json
{
  "query": "tag:peexe positives:5+",
  "limit": 10
}
```

#### 9. vt_get_comments
Get community comments for a VirusTotal object.

**Parameters:**
- `object_id`: Object ID (hash/URL ID) (required)
- `object_type`: Type: "files", "urls", "domains", "ip_addresses" (default: "files")

**Example:**
```json
{
  "object_id": "d41d8cd98f00b204e9800998ecf8427e",
  "object_type": "files"
}
```

### Local File Analysis

#### 10. calculate_hashes
Calculate multiple hash values (MD5, SHA1, SHA256, SHA512, SSDEEP) for a file.

**Parameters:**
- `file_path`: Path to file (required)

**Example:**
```json
{
  "file_path": "/home/user/samples/malware.exe"
}
```

#### 11. extract_strings
Extract readable strings from a binary file.

**Parameters:**
- `file_path`: Path to file (required)
- `min_length`: Minimum string length (default: 4)

**Example:**
```json
{
  "file_path": "/home/user/samples/malware.exe",
  "min_length": 4
}
```

#### 12. extract_exif
Extract EXIF and metadata from files using ExifTool.

**Parameters:**
- `file_path`: Path to file (required)

**Example:**
```json
{
  "file_path": "/home/user/evidence/image.jpg"
}
```

#### 13. die_analyze_file
Analyze file with Detect It Easy (DIE) - detects packers, compilers, etc.

**Parameters:**
- `file_path`: Path to file (required)

**Example:**
```json
{
  "file_path": "/home/user/samples/packed.exe"
}
```

### Firmware Analysis

#### 14. binwalk_scan
Scan file for embedded signatures (firmware, compressed data, etc.).

**Parameters:**
- `file_path`: Path to file (required)

**Example:**
```json
{
  "file_path": "/home/user/firmware/router.bin"
}
```

#### 15. binwalk_extract
Extract embedded files from firmware/binary.

**Parameters:**
- `file_path`: Path to file (required)
- `output_dir`: Output directory (optional)

**Example:**
```json
{
  "file_path": "/home/user/firmware/router.bin",
  "output_dir": "/home/user/extracted"
}
```

### Cache Management

#### 16. get_cache_stats
Get cache statistics.

**Example:**
```json
{}
```

#### 17. clear_cache
Clear all cache entries.

**Example:**
```json
{}
```

## Usage Examples

### Malware Analysis Workflow
```
Analyze this suspicious executable and provide a detailed report.
File: /home/user/samples/suspicious.exe

Steps:
1. Calculate hashes
2. Check VirusTotal reputation
3. Analyze with DIE
4. Extract strings
5. Scan for embedded files with binwalk
```

### URL Investigation
```
Investigate this suspicious URL and provide threat intelligence.
URL: http://suspicious-domain.com

Steps:
1. Get URL report from VirusTotal
2. Get domain report
3. Check IP reputation
```

### Firmware Analysis
```
Analyze this firmware image and extract embedded files.
File: /home/user/firmware/router.bin

Steps:
1. Scan with binwalk
2. Extract all embedded files
3. Calculate hashes of extracted files
4. Check hashes on VirusTotal
```

### Metadata Extraction
```
Extract all metadata from this image file.
File: /home/user/evidence/photo.jpg

Steps:
1. Extract EXIF data
2. Extract strings
3. Calculate hashes
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  MCP Server      │────▶│   VirusTotal    │
│ (Claude/VSCode) │     │  (Python/MCP)    │     │     API         │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                           │
                               ▼                           │
                        ┌─────────────────┐                │
                        │  Memory Cache   │                │
                        │  (200MB limit)  │                │
                        └─────────────────┘                │
                               │                           ▼
                               ▼                  ┌─────────────────┐
                        ┌──────────────┐          │  Local Tools    │
                        │ Local Tools  │          │  (DIE, ExifTool,│
                        │  (Hash,      │          │   Binwalk)      │
                        │  Strings,    │          └─────────────────┘
                        │  EXIF)       │
                        └──────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │ Target File  │
                        └──────────────┘
```

## Caching System

The server implements an intelligent in-memory caching system:

- **Cache Key Format**: `{tool_type}:{file_path}` or `vt:{endpoint}:{identifier}`
- **Size Limit**: 200MB with LRU eviction
- **Scope**: Per-instance (clears on restart)
- **Benefits**: 
  - Avoids re-calculating hashes
  - Reduces VirusTotal API calls
  - Faster repeated analysis

## Project Structure

```
forensics-utils-mcp-server/
├── forensics_utils_mcp_server/
│   ├── __init__.py
│   ├── server.py              # MCP server entry point
│   ├── cache.py               # In-memory cache implementation
│   ├── config.py              # Configuration settings
│   ├── exceptions.py          # Custom exceptions
│   ├── queue.py               # Rate-limited request queue
│   ├── vt_client.py           # VirusTotal API client
│   └── tools/
│       ├── __init__.py
│       ├── file_tools.py      # VT file analysis
│       ├── url_tools.py       # VT URL analysis
│       ├── domain_tools.py    # VT domain/IP analysis
│       ├── search_tools.py    # VT search
│       ├── hash_tools.py      # Hash calculation
│       ├── string_tools.py    # String extraction
│       ├── exif_tools.py      # EXIF extraction
│       ├── die_tools.py       # DIE analysis
│       └── binwalk_tools.py   # Binwalk integration
├── tests/
│   └── test_server.py
├── .env.example
├── .gitignore
├── pyproject.toml
├── README.md
└── requirements.txt
```

## Development

### Setup Development Environment
```bash
pip install -e ".[dev]"
```

### Code Quality
```bash
black forensics_utils_mcp_server
mypy forensics_utils_mcp_server
```

### Testing
```bash
pytest tests/
```

## Security Features

- **API Key Protection**: Stored in `.env`, never committed to git
- **Path Validation**: Local-file tools (`calculate_hashes`, `extract_strings`,
  `extract_exif`, `die_analyze_file`, `binwalk_*`, `vt_scan_file`) require an
  absolute path that points to an existing regular file. Browser-artifact tools
  require an existing directory. All other input is forwarded unchanged.
- **Size Limits**: File upload limited to 32MB for VirusTotal
- **Rate Limiting**: 4 requests/minute for VT API
- **Timeout Protection**: Request timeout configuration (default: 60s)

## Troubleshooting

### VirusTotal API Key Not Found
```bash
# Create .env file
echo "VIRUSTOTAL_API_KEY=your_key_here" > .env
```

### DIE Not Found
```bash
# Download DIE from releases
# https://github.com/horsicq/Detect-It-Easy/releases
# Extract and add diec to PATH
```

### Binwalk Not Found
```bash
pip install binwalk
```

### ExifTool Not Found
```bash
# Windows: Download from https://exiftool.org/install.html
# Linux: sudo apt-get install libimage-exiftool-perl
# macOS: brew install exiftool
```

## Rate Limits

- **VirusTotal Free Tier**: 4 requests/minute
- **VirusTotal Paid Tier**: Up to 10,000+ requests/day

Adjust in `forensics_utils_mcp_server/config.py`:
```python
QUEUE_RATE_LIMIT = 4  # requests per minute
QUEUE_TIMEOUT_SECONDS = 60
```

## Changelog

### v1.0.0 - Initial Release
- VirusTotal API v3 integration (9 tools)
- Local analysis tools (6 tools)
- In-memory caching system
- Rate limiting and queue management
- Support for DIE, ExifTool, Binwalk

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) - Threat intelligence platform
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) - File identifier
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis tool
- [ExifTool](https://exiftool.org/) - Metadata reader/writer
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [python-mcp](https://github.com/modelcontextprotocol/python-sdk) - Python MCP SDK

## Support

For issues and feature requests, please use the [GitHub issue tracker](https://github.com/jus1-c/forensics-utils-mcp-server/issues).
