"""Forensics MCP Server implementation."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastmcp import FastMCP, Context

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.config import SERVER_NAME, SERVER_VERSION
from forensics_utils_mcp_server.queue import queue
from forensics_utils_mcp_server.tools import (
    # VirusTotal File
    vt_scan_file,
    vt_get_file_report,
    vt_get_file_behavior,
    # VirusTotal URL
    vt_scan_url,
    vt_get_url_report,
    # VirusTotal Domain/IP
    vt_get_domain_report,
    vt_get_ip_report,
    # VirusTotal Search
    vt_search_files,
    vt_get_comments,
    # Local Tools
    die_analyze_file,
    calculate_hashes,
    extract_exif,
    extract_strings,
    # Binwalk
    binwalk_scan,
    binwalk_extract,
    # Firefox Artifacts
    firefox_profile_summary,
    firefox_parse_history,
    firefox_parse_bookmarks,
    firefox_parse_downloads,
    firefox_parse_cookies,
    firefox_decrypt_cookies,
    firefox_parse_sessions,
    firefox_parse_session_storage,
    firefox_parse_favicons,
    firefox_parse_extensions,
    firefox_parse_preferences,
    firefox_parse_logins,
    firefox_parse_web_data,
    firefox_parse_local_storage,
    firefox_parse_indexeddb,
    firefox_parse_cache,
    firefox_decrypt_logins,
    # Chromium Deep Artifacts
    chromium_profile_summary,
    chromium_parse_local_storage,
    chromium_parse_session_storage,
    chromium_parse_indexeddb,
    chromium_parse_cache,
    chromium_parse_history,
    chromium_parse_downloads,
    chromium_parse_sessions,
    chromium_parse_favicons,
    chromium_parse_web_data,
    chromium_parse_extensions,
    chromium_parse_preferences,
    chromium_parse_bookmarks,
    chromium_parse_logins,
    chromium_decrypt_logins,
    chromium_parse_cookies,
    chromium_decrypt_cookies,
)


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Manage application lifecycle."""
    await queue.start()
    print(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    print("Cache initialized")
    print("Rate-limited queue started (4 req/min)")

    yield {"server": server}

    await queue.stop()
    print(f"Shutting down {SERVER_NAME}")


mcp = FastMCP(SERVER_NAME, lifespan=app_lifespan)


# ==================== VirusTotal File Tools ====================


@mcp.tool()
async def vt_scan_file_tool(file_path: str, ctx: Context) -> dict:
    """
    Scan a file using VirusTotal.

    For files smaller than 32MB, uploads the file directly.
    For larger files, calculates hash and checks VirusTotal database.

    Args:
        file_path: Path to the file to scan

    Returns:
        JSON object containing scan results or hash lookup results
    """
    await ctx.info(f"Scanning file: {file_path}")
    return await vt_scan_file(file_path)


@mcp.tool()
async def vt_get_file_report_tool(file_hash: str, ctx: Context) -> dict:
    """
    Get VirusTotal analysis report for a file by its hash.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash of the file

    Returns:
        JSON object containing the file analysis report
    """
    await ctx.info(f"Getting file report for hash: {file_hash}")
    return await vt_get_file_report(file_hash)


@mcp.tool()
async def vt_get_file_behavior_tool(file_hash: str, ctx: Context) -> dict:
    """
    Get behavior summary for a file analyzed in VirusTotal's sandbox.

    Args:
        file_hash: SHA256 hash of the file

    Returns:
        JSON object containing sandbox behavior analysis
    """
    await ctx.info(f"Getting file behavior for hash: {file_hash}")
    return await vt_get_file_behavior(file_hash)


# ==================== VirusTotal URL Tools ====================


@mcp.tool()
async def vt_scan_url_tool(url: str, ctx: Context) -> dict:
    """
    Submit a URL to VirusTotal for scanning.

    Args:
        url: The URL to scan (e.g., "http://example.com")

    Returns:
        JSON object containing scan submission results or existing analysis
    """
    await ctx.info(f"Scanning URL: {url}")
    return await vt_scan_url(url)


@mcp.tool()
async def vt_get_url_report_tool(url: str, ctx: Context) -> dict:
    """
    Get VirusTotal analysis report for a URL.

    Args:
        url: The URL to get the report for

    Returns:
        JSON object containing URL analysis report
    """
    await ctx.info(f"Getting URL report for: {url}")
    return await vt_get_url_report(url)


# ==================== VirusTotal Domain/IP Tools ====================


@mcp.tool()
async def vt_get_domain_report_tool(domain: str, ctx: Context) -> dict:
    """
    Get VirusTotal intelligence report for a domain.

    Includes: WHOIS data, DNS records, SSL certificates, reputation score,
    and related files/URLs.

    Args:
        domain: The domain name (e.g., "example.com")

    Returns:
        JSON object containing domain intelligence report
    """
    await ctx.info(f"Getting domain report for: {domain}")
    return await vt_get_domain_report(domain)


@mcp.tool()
async def vt_get_ip_report_tool(ip: str, ctx: Context) -> dict:
    """
    Get VirusTotal intelligence report for an IP address.

    Includes: Geolocation, ASN information, reputation score,
    related files, URLs, and domains.

    Args:
        ip: The IP address (e.g., "8.8.8.8")

    Returns:
        JSON object containing IP reputation report
    """
    await ctx.info(f"Getting IP report for: {ip}")
    return await vt_get_ip_report(ip)


# ==================== VirusTotal Search Tools ====================


@mcp.tool()
async def vt_search_files_tool(query: str, ctx: Context, limit: int = 10) -> dict:
    """
    Search for files using VirusTotal Intelligence.

    Supports advanced search syntax:
    - tag:peexe (PE executables)
    - positives:5+ (files with 5+ detections)
    - fs:2023-01-01+ (first seen after date)
    - content:{ "magic": "PE32" } (YARA-style content search)

    Args:
        query: Search query string
        limit: Maximum number of results (default: 10)

    Returns:
        JSON object containing search results
    """
    await ctx.info(f"Searching VirusTotal for: {query}")
    return await vt_search_files(query, limit)


@mcp.tool()
async def vt_get_comments_tool(
    object_id: str, ctx: Context, object_type: str = "files"
) -> dict:
    """
    Get community comments for a VirusTotal object.

    Args:
        object_id: The ID of the object (hash for files, URL ID for URLs)
        object_type: Type of object ("files", "urls", "domains", "ip_addresses")

    Returns:
        JSON object containing community comments and votes
    """
    await ctx.info(f"Getting comments for {object_type}: {object_id}")
    return await vt_get_comments(object_id, object_type)


# ==================== Detect It Easy Tool ====================


@mcp.tool()
async def die_analyze_file_tool(file_path: str, ctx: Context) -> dict:
    """
    Analyze a file using Detect It Easy (DIE) with deep scan mode.

    Uses flags: -a (all types), -u (heuristic scan), --verbose, -j (JSON output)

    Returns detailed analysis including:
    - Packer/Compiler detection
    - Entropy analysis
    - Section details
    - Import/Export tables
    - Resources info
    - Signature matches
    - Heuristic detections

    Args:
        file_path: Path to the file to analyze

    Returns:
        JSON object containing detailed file analysis

    Note:
        Requires DIE to be installed and available in PATH.
        Download from: https://github.com/horsicq/Detect-It-Easy
    """
    await ctx.info(f"Analyzing file with DIE: {file_path}")
    return await die_analyze_file(file_path)


# ==================== Hash Calculation Tool ====================


@mcp.tool()
async def calculate_hashes_tool(file_path: str, ctx: Context) -> dict:
    """
    Calculate multiple hash values for a file.

    Calculates: MD5, SHA1, SHA256, SHA512, and SSDEEP (if available)

    Args:
        file_path: Path to the file

    Returns:
        JSON object containing all hash values
    """
    await ctx.info(f"Calculating hashes for: {file_path}")
    return await calculate_hashes(file_path)


# ==================== EXIF Extraction Tool ====================


@mcp.tool()
async def extract_exif_tool(file_path: str, ctx: Context) -> dict:
    """
    Extract EXIF and metadata from a file using ExifTool.

    Supports images, documents, media files, and many other formats.
    Extracts: camera info, GPS coordinates, timestamps, software versions,
    author information, and hundreds of other metadata fields.

    Args:
        file_path: Path to the file

    Returns:
        JSON object containing all metadata fields

    Note:
        Requires ExifTool to be installed and available in PATH.
        Install: https://exiftool.org/install.html
    """
    await ctx.info(f"Extracting EXIF metadata from: {file_path}")
    return await extract_exif(file_path)


# ==================== String Extraction Tool ====================


@mcp.tool()
async def extract_strings_tool(
    file_path: str, ctx: Context, min_length: int = 4
) -> dict:
    """
    Extract readable strings from a binary file.

    Useful for analyzing malware, finding embedded URLs, file paths,
    error messages, and other interesting artifacts.

    Args:
        file_path: Path to the file
        min_length: Minimum string length to include (default: 4)

    Returns:
        JSON object containing extracted ASCII and Unicode strings
    """
    await ctx.info(f"Extracting strings from: {file_path}")
    return await extract_strings(file_path, min_length)


# ==================== Binwalk Tools ====================


@mcp.tool()
async def binwalk_scan_tool(file_path: str, ctx: Context) -> dict:
    """
    Scan a file for embedded signatures using binwalk.

    Detects file signatures, archives, compressed data, and other
    embedded file types within binary data. Useful for firmware
    analysis, memory dumps, and packed executables.

    Args:
        file_path: Path to the file to scan

    Returns:
        JSON object containing detected signatures with offsets and descriptions

    Note:
        Requires binwalk to be installed.
        Install: pip install binwalk
    """
    await ctx.info(f"Scanning file with binwalk: {file_path}")
    return await binwalk_scan(file_path)


@mcp.tool()
async def binwalk_extract_tool(
    file_path: str, ctx: Context, output_dir: str = None
) -> dict:
    """
    Extract embedded files from a binary using binwalk.

    Automatically extracts known file types (ZIP, ELF, etc.) found
    within the binary. Uses recursive extraction to handle nested
    archives.

    Args:
        file_path: Path to the file to extract from
        output_dir: Optional custom extraction directory. When omitted,
            files are written to ``./extractions/<filename>/``.

    Returns:
        JSON object containing extraction results and list of extracted files

    Note:
        Requires binwalk to be installed.
    """
    await ctx.info(f"Extracting embedded files from: {file_path}")
    return await binwalk_extract(file_path, output_dir)


# ==================== Cache Management Tools ====================


# ==================== Firefox Artifact Tools ====================


@mcp.tool()
async def firefox_profile_summary_tool(
    profile_path: str, ctx: Context, sample_limit: int = 10
) -> dict:
    """
    Summarize basic Firefox artifacts available in a browser profile.
    Typical Firefox profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".
    Extract with disk-forensics first, then point this tool at the extracted directory.

    Detects whether history, bookmarks, downloads, cookies, sessions, favicons,
    extensions, preferences, and login metadata artifacts are present.

    Args:
        profile_path: Absolute path to the Firefox profile directory
        sample_limit: Maximum number of sample identifiers per artifact

    Returns:
        JSON object describing which Firefox artifacts are available
    """
    await ctx.info(f"Summarizing Firefox profile: {profile_path}")
    return await firefox_profile_summary(profile_path, sample_limit)


@mcp.tool()
async def firefox_parse_history_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox browsing history records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        url: Optional exact URL filter
        title: Optional exact page title filter
        limit: Maximum number of history records to return

    Returns:
        JSON object containing Firefox history records
    """
    await ctx.info(f"Parsing Firefox history from: {profile_path}")
    return await firefox_parse_history(profile_path, url=url, title=title, limit=limit)


@mcp.tool()
async def firefox_parse_bookmarks_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox bookmark entries from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        url: Optional exact bookmark URL filter
        title: Optional exact bookmark title filter
        limit: Maximum number of bookmark entries to return

    Returns:
        JSON object containing Firefox bookmark records
    """
    await ctx.info(f"Parsing Firefox bookmarks from: {profile_path}")
    return await firefox_parse_bookmarks(profile_path, url=url, title=title, limit=limit)


@mcp.tool()
async def firefox_parse_downloads_tool(
    profile_path: str,
    ctx: Context,
    download_url: str = None,
    source_url: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox download candidates from a browser profile.

    Args:
        profile_path: Absolute path to the Firefox profile directory
        download_url: Optional exact downloaded file URL filter
        source_url: Optional exact referring/source URL filter
        limit: Maximum number of download records to return

    Returns:
        JSON object containing Firefox download candidate records
    """
    await ctx.info(f"Parsing Firefox downloads from: {profile_path}")
    return await firefox_parse_downloads(
        profile_path,
        download_url=download_url,
        source_url=source_url,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_cookies_tool(
    profile_path: str,
    ctx: Context,
    host: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox cookies from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        host: Optional exact cookie host filter
        name: Optional exact cookie name filter
        limit: Maximum number of cookie records to return

    Returns:
        JSON object containing Firefox cookie records
    """
    await ctx.info(f"Parsing Firefox cookies from: {profile_path}")
    return await firefox_parse_cookies(profile_path, host=host, name=name, limit=limit)


@mcp.tool()
async def firefox_decrypt_cookies_tool(
    profile_path: str,
    ctx: Context,
    host: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Return Firefox cookies as already-decrypted plaintext values.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Firefox stores cookies plaintext in cookies.sqlite, so this tool provides
    parity with Chromium-style decrypt flows by normalizing plaintext values
    into a decrypt-oriented response.

    Args:
        profile_path: Absolute path to the Firefox profile directory
        host: Optional exact cookie host filter
        name: Optional exact cookie name filter
        limit: Maximum number of cookie records to return

    Returns:
        JSON object containing plaintext Firefox cookie values
    """
    await ctx.info(f"Decrypting Firefox cookies from: {profile_path}")
    return await firefox_decrypt_cookies(profile_path, host=host, name=name, limit=limit)


@mcp.tool()
async def firefox_parse_sessions_tool(
    profile_path: str,
    ctx: Context,
    file_name: str = None,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox session restore files from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        file_name: Optional exact session file name filter
        url: Optional exact URL filter
        title: Optional exact page title filter
        limit: Maximum number of session navigation records to return

    Returns:
        JSON object containing Firefox session navigation entries
    """
    await ctx.info(f"Parsing Firefox sessions from: {profile_path}")
    return await firefox_parse_sessions(
        profile_path,
        file_name=file_name,
        url=url,
        title=title,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_session_storage_tool(
    profile_path: str,
    ctx: Context,
    host: str = None,
    key: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox session storage records when sessionstore contains them.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        host: Optional exact session storage host/origin filter
        key: Optional exact session storage key filter
        limit: Maximum number of session storage records to return

    Returns:
        JSON object containing Firefox session storage records
    """
    await ctx.info(f"Parsing Firefox session storage from: {profile_path}")
    return await firefox_parse_session_storage(
        profile_path,
        host=host,
        key=key,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_favicons_tool(
    profile_path: str,
    ctx: Context,
    page_url: str = None,
    icon_url: str = None,
    limit: int = 100,
    include_image: bool = False,
    max_image_bytes: int = 4096,
) -> dict:
    """
    Parse Firefox favicons from the favicons database.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        page_url: Optional exact page URL filter
        icon_url: Optional exact favicon URL filter
        limit: Maximum number of favicon records to return
        include_image: Include favicon image previews as base64
        max_image_bytes: Maximum bytes to include per image preview

    Returns:
        JSON object containing Firefox favicon records
    """
    await ctx.info(f"Parsing Firefox favicons from: {profile_path}")
    return await firefox_parse_favicons(
        profile_path,
        page_url=page_url,
        icon_url=icon_url,
        limit=limit,
        include_image=include_image,
        max_image_bytes=max_image_bytes,
    )


@mcp.tool()
async def firefox_parse_extensions_tool(
    profile_path: str,
    ctx: Context,
    extension_id: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox installed extension metadata.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        extension_id: Optional exact extension ID filter
        name: Optional exact extension name filter
        limit: Maximum number of extension records to return

    Returns:
        JSON object containing Firefox extension metadata records
    """
    await ctx.info(f"Parsing Firefox extensions from: {profile_path}")
    return await firefox_parse_extensions(
        profile_path,
        extension_id=extension_id,
        name=name,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_preferences_tool(
    profile_path: str,
    ctx: Context,
    key_path: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox preferences from prefs.js.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        key_path: Optional exact preference key filter
        limit: Maximum number of preference entries to return

    Returns:
        JSON object containing Firefox preference entries
    """
    await ctx.info(f"Parsing Firefox preferences from: {profile_path}")
    return await firefox_parse_preferences(profile_path, key_path=key_path, limit=limit)


@mcp.tool()
async def firefox_parse_logins_tool(
    profile_path: str,
    ctx: Context,
    hostname: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox saved-login metadata from logins.json.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        hostname: Optional exact hostname filter
        limit: Maximum number of login metadata records to return

    Returns:
        JSON object containing Firefox login metadata
    """
    await ctx.info(f"Parsing Firefox logins from: {profile_path}")
    return await firefox_parse_logins(profile_path, hostname=hostname, limit=limit)


@mcp.tool()
async def firefox_parse_web_data_tool(
    profile_path: str,
    ctx: Context,
    category: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox web-data-like artifacts such as form history, permissions,
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".
    content preferences, and search engines.

    Args:
        profile_path: Absolute path to the Firefox profile directory
        category: Optional exact category filter (`form_history`, `permissions`, `content_prefs`, `search_engines`)
        limit: Maximum number of records to return

    Returns:
        JSON object containing Firefox web data records
    """
    await ctx.info(f"Parsing Firefox web data from: {profile_path}")
    return await firefox_parse_web_data(profile_path, category=category, limit=limit)


@mcp.tool()
async def firefox_parse_local_storage_tool(
    profile_path: str,
    ctx: Context,
    origin_key: str = None,
    key: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox local storage records from webappsstore and storage/default/ls.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        origin_key: Optional exact origin/storage key filter
        key: Optional exact local storage key filter
        limit: Maximum number of local storage records to return

    Returns:
        JSON object containing Firefox local storage records
    """
    await ctx.info(f"Parsing Firefox local storage from: {profile_path}")
    return await firefox_parse_local_storage(
        profile_path,
        origin_key=origin_key,
        key=key,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_indexeddb_tool(
    profile_path: str,
    ctx: Context,
    host_id: str = None,
    database_name: str = None,
    object_store_name: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Firefox IndexedDB records from storage/default/*/idb.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        host_id: Optional exact storage/default origin directory filter
        database_name: Optional exact IndexedDB database name filter
        object_store_name: Optional exact object store filter
        limit: Maximum number of IndexedDB records to return

    Returns:
        JSON object containing Firefox IndexedDB records
    """
    await ctx.info(f"Parsing Firefox IndexedDB from: {profile_path}")
    return await firefox_parse_indexeddb(
        profile_path,
        host_id=host_id,
        database_name=database_name,
        object_store_name=object_store_name,
        limit=limit,
    )


@mcp.tool()
async def firefox_parse_cache_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    limit: int = 100,
    include_body: bool = False,
    max_body_bytes: int = 16384,
) -> dict:
    """
    Parse Firefox cache records from storage/default/*/cache.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".

    Args:
        profile_path: Absolute path to the Firefox profile directory
        url: Optional exact request URL filter
        limit: Maximum number of cache records to return
        include_body: Include cached body previews when the morgue file is present
        max_body_bytes: Maximum bytes to include per body preview

    Returns:
        JSON object containing Firefox cache records
    """
    await ctx.info(f"Parsing Firefox cache from: {profile_path}")
    return await firefox_parse_cache(
        profile_path,
        url=url,
        limit=limit,
        include_body=include_body,
        max_body_bytes=max_body_bytes,
    )


@mcp.tool()
async def firefox_decrypt_logins_tool(
    profile_path: str,
    ctx: Context,
    primary_password: str = None,
    hostname: str = None,
    limit: int = 100,
    nss_lib_path: str = None,
) -> dict:
    """
    Attempt to decrypt Firefox saved passwords via firefox_decrypt.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<rand>.default-release".
    Requires NSS libs and optional primary_password.

    Args:
        profile_path: Absolute path to the Firefox profile directory
        primary_password: Optional primary password. Leave empty or unset if none is configured
        hostname: Optional exact hostname filter
        limit: Maximum number of decrypted login records to return
        nss_lib_path: Optional path to an NSS library directory for firefox_decrypt

    Returns:
        JSON object containing decrypted Firefox login records
    """
    await ctx.info(f"Decrypting Firefox logins from: {profile_path}")
    return await firefox_decrypt_logins(
        profile_path,
        primary_password=primary_password,
        hostname=hostname,
        limit=limit,
        nss_lib_path=nss_lib_path,
    )


# ==================== Chromium Deep Artifact Tools ====================


@mcp.tool()
async def chromium_profile_summary_tool(
    profile_path: str, ctx: Context, sample_limit: int = 10
) -> dict:
    """
    Summarize deep Chromium artifacts available in a browser profile.
    Typical Chromium profile paths: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default" (Chrome) or "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default" (Edge).
    Extract with disk-forensics first, then point this tool at the extracted directory.

    Detects whether Local Storage, Session Storage, IndexedDB, and Cache
    are present and returns a small sample of the content identifiers for each.

    Args:
        profile_path: Absolute path to the Chromium profile directory
        sample_limit: Maximum number of sample identifiers per artifact

    Returns:
        JSON object describing which deep Chromium artifacts are available
    """
    await ctx.info(f"Summarizing Chromium profile: {profile_path}")
    return await chromium_profile_summary(profile_path, sample_limit)


@mcp.tool()
async def chromium_parse_local_storage_tool(
    profile_path: str,
    ctx: Context,
    storage_key: str = None,
    script_key: str = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """
    Parse Chromium Local Storage records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        storage_key: Optional exact storage key/origin filter
        script_key: Optional exact Local Storage key filter
        limit: Maximum number of records to return
        include_deletions: Include recovered deletion records when available

    Returns:
        JSON object containing Local Storage records
    """
    await ctx.info(f"Parsing Chromium Local Storage from: {profile_path}")
    return await chromium_parse_local_storage(
        profile_path,
        storage_key=storage_key,
        script_key=script_key,
        limit=limit,
        include_deletions=include_deletions,
    )


@mcp.tool()
async def chromium_parse_session_storage_tool(
    profile_path: str,
    ctx: Context,
    host: str = None,
    key: str = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """
    Parse Chromium Session Storage records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        host: Optional exact host filter
        key: Optional exact Session Storage key filter
        limit: Maximum number of records to return
        include_deletions: Include recovered deletion records when available

    Returns:
        JSON object containing Session Storage records
    """
    await ctx.info(f"Parsing Chromium Session Storage from: {profile_path}")
    return await chromium_parse_session_storage(
        profile_path,
        host=host,
        key=key,
        limit=limit,
        include_deletions=include_deletions,
    )


@mcp.tool()
async def chromium_parse_indexeddb_tool(
    profile_path: str,
    ctx: Context,
    host_id: str = None,
    database_name: str = None,
    object_store_name: str = None,
    limit: int = 100,
    include_deletions: bool = False,
) -> dict:
    """
    Parse Chromium IndexedDB records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        host_id: Optional exact IndexedDB host/origin directory filter
        database_name: Optional exact IndexedDB database name filter
        object_store_name: Optional exact object store filter
        limit: Maximum number of records to return
        include_deletions: Include deleted/non-live records when available

    Returns:
        JSON object containing IndexedDB records
    """
    await ctx.info(f"Parsing Chromium IndexedDB from: {profile_path}")
    return await chromium_parse_indexeddb(
        profile_path,
        host_id=host_id,
        database_name=database_name,
        object_store_name=object_store_name,
        limit=limit,
        include_deletions=include_deletions,
    )


@mcp.tool()
async def chromium_parse_cache_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    limit: int = 100,
    include_body: bool = False,
    max_body_bytes: int = 16384,
    decompress: bool = True,
) -> dict:
    """
    Parse Chromium HTTP cache records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        url: Optional exact URL filter
        limit: Maximum number of cache records to return
        include_body: Include cached response bodies as base64 previews
        max_body_bytes: Maximum number of bytes to include per cached body preview
        decompress: Decompress gzip/brotli/deflate responses when possible

    Returns:
        JSON object containing Chromium cache metadata and optional body previews
    """
    await ctx.info(f"Parsing Chromium cache from: {profile_path}")
    return await chromium_parse_cache(
        profile_path,
        url=url,
        limit=limit,
        include_body=include_body,
        max_body_bytes=max_body_bytes,
        decompress=decompress,
    )


@mcp.tool()
async def chromium_parse_history_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium browsing history records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        url: Optional exact URL filter
        title: Optional exact page title filter
        limit: Maximum number of history records to return

    Returns:
        JSON object containing Chromium history records
    """
    await ctx.info(f"Parsing Chromium history from: {profile_path}")
    return await chromium_parse_history(
        profile_path,
        url=url,
        title=title,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_downloads_tool(
    profile_path: str,
    ctx: Context,
    download_url: str = None,
    tab_url: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium download records from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Reads downloads from both the History database and shared_proto_db when present.

    Args:
        profile_path: Absolute path to the Chromium profile directory
        download_url: Optional exact downloaded URL filter
        tab_url: Optional exact originating tab URL filter
        limit: Maximum number of download records to return

    Returns:
        JSON object containing Chromium download records
    """
    await ctx.info(f"Parsing Chromium downloads from: {profile_path}")
    return await chromium_parse_downloads(
        profile_path,
        download_url=download_url,
        tab_url=tab_url,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_sessions_tool(
    profile_path: str,
    ctx: Context,
    file_name: str = None,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium session restore files from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        file_name: Optional exact session file name filter
        url: Optional exact URL filter
        title: Optional exact page title filter
        limit: Maximum number of session navigation records to return

    Returns:
        JSON object containing Chromium session navigation entries
    """
    await ctx.info(f"Parsing Chromium sessions from: {profile_path}")
    return await chromium_parse_sessions(
        profile_path,
        file_name=file_name,
        url=url,
        title=title,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_favicons_tool(
    profile_path: str,
    ctx: Context,
    page_url: str = None,
    icon_url: str = None,
    limit: int = 100,
    include_image: bool = False,
    max_image_bytes: int = 4096,
) -> dict:
    """
    Parse Chromium favicons from the Favicons database.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        page_url: Optional exact page URL filter
        icon_url: Optional exact favicon URL filter
        limit: Maximum number of favicon records to return
        include_image: Include favicon image previews as base64
        max_image_bytes: Maximum bytes to include per image preview

    Returns:
        JSON object containing Chromium favicon records
    """
    await ctx.info(f"Parsing Chromium favicons from: {profile_path}")
    return await chromium_parse_favicons(
        profile_path,
        page_url=page_url,
        icon_url=icon_url,
        limit=limit,
        include_image=include_image,
        max_image_bytes=max_image_bytes,
    )


@mcp.tool()
async def chromium_parse_web_data_tool(
    profile_path: str,
    ctx: Context,
    category: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse common Chromium Web Data tables.

    Supports categories such as autofill, keywords, and profiles when present.

    Args:
        profile_path: Absolute path to the Chromium profile directory
        category: Optional exact Web Data category filter
        limit: Maximum number of records to return

    Returns:
        JSON object containing Web Data records
    """
    await ctx.info(f"Parsing Chromium Web Data from: {profile_path}")
    return await chromium_parse_web_data(
        profile_path,
        category=category,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_extensions_tool(
    profile_path: str,
    ctx: Context,
    extension_id: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium installed extension metadata.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        extension_id: Optional exact extension ID filter
        name: Optional exact extension name filter
        limit: Maximum number of extension records to return

    Returns:
        JSON object containing extension metadata records
    """
    await ctx.info(f"Parsing Chromium extensions from: {profile_path}")
    return await chromium_parse_extensions(
        profile_path,
        extension_id=extension_id,
        name=name,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_preferences_tool(
    profile_path: str,
    ctx: Context,
    key_path: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium Preferences and Secure Preferences data.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        key_path: Optional dot-separated preference path filter
        limit: Maximum number of preference entries to return

    Returns:
        JSON object containing Chromium preference entries
    """
    await ctx.info(f"Parsing Chromium preferences from: {profile_path}")
    return await chromium_parse_preferences(
        profile_path,
        key_path=key_path,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_bookmarks_tool(
    profile_path: str,
    ctx: Context,
    url: str = None,
    title: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium bookmark URL entries from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Args:
        profile_path: Absolute path to the Chromium profile directory
        url: Optional exact bookmark URL filter
        title: Optional exact bookmark title filter
        limit: Maximum number of bookmark entries to return

    Returns:
        JSON object containing Chromium bookmark entries
    """
    await ctx.info(f"Parsing Chromium bookmarks from: {profile_path}")
    return await chromium_parse_bookmarks(
        profile_path,
        url=url,
        title=title,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_cookies_tool(
    profile_path: str,
    ctx: Context,
    host_key: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium cookies from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Supports both legacy `Cookies` and modern `Network/Cookies` SQLite locations.

    Args:
        profile_path: Absolute path to the Chromium profile directory
        host_key: Optional exact cookie domain filter
        name: Optional exact cookie name filter
        limit: Maximum number of cookie records to return

    Returns:
        JSON object containing Chromium cookie records
    """
    await ctx.info(f"Parsing Chromium cookies from: {profile_path}")
    return await chromium_parse_cookies(
        profile_path,
        host_key=host_key,
        name=name,
        limit=limit,
    )


@mcp.tool()
async def chromium_decrypt_cookies_tool(
    profile_path: str,
    ctx: Context,
    local_state_path: str = None,
    master_key_b64: str = None,
    host_key: str = None,
    name: str = None,
    limit: int = 100,
) -> dict:
    """
    Attempt to decrypt Chromium cookies from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Supports two modes:
    - Windows current-user context using `Local State` + DPAPI
    - Offline decryption when a decrypted Chromium master key is supplied via `master_key_b64`

    Args:
        profile_path: Absolute path to the Chromium profile directory
        local_state_path: Optional path to the Chromium `Local State` file
        master_key_b64: Optional decrypted Chromium master key in base64 form
        host_key: Optional exact cookie domain filter
        name: Optional exact cookie name filter
        limit: Maximum number of cookie records to return

    Returns:
        JSON object containing per-record cookie decryption status
    """
    await ctx.info(f"Decrypting Chromium cookies from: {profile_path}")
    return await chromium_decrypt_cookies(
        profile_path,
        local_state_path=local_state_path,
        master_key_b64=master_key_b64,
        host_key=host_key,
        name=name,
        limit=limit,
    )


@mcp.tool()
async def chromium_parse_logins_tool(
    profile_path: str,
    ctx: Context,
    origin_url: str = None,
    username_value: str = None,
    limit: int = 100,
) -> dict:
    """
    Parse Chromium saved-login metadata from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default" (or Edge).
    On Windows the Local State file is required for v10/v11 decryption.

    Reads the `Login Data` database and returns login metadata without decrypting passwords.

    Args:
        profile_path: Absolute path to the Chromium profile directory
        origin_url: Optional exact origin URL filter
        username_value: Optional exact username filter
        limit: Maximum number of login records to return

    Returns:
        JSON object containing Chromium saved-login metadata
    """
    await ctx.info(f"Parsing Chromium logins from: {profile_path}")
    return await chromium_parse_logins(
        profile_path,
        origin_url=origin_url,
        username_value=username_value,
        limit=limit,
    )


@mcp.tool()
async def chromium_decrypt_logins_tool(
    profile_path: str,
    ctx: Context,
    local_state_path: str = None,
    master_key_b64: str = None,
    origin_url: str = None,
    username_value: str = None,
    limit: int = 100,
) -> dict:
    """
    Attempt to decrypt Chromium saved passwords from a browser profile.
    Typical profile path: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default".

    Supports two modes:
    - Windows current-user context using `Local State` + DPAPI
    - Offline decryption when a decrypted Chromium master key is supplied via `master_key_b64`

    Args:
        profile_path: Absolute path to the Chromium profile directory
        local_state_path: Optional path to the Chromium `Local State` file
        master_key_b64: Optional decrypted Chromium master key in base64 form
        origin_url: Optional exact origin URL filter
        username_value: Optional exact username filter
        limit: Maximum number of login records to return

    Returns:
        JSON object containing per-record decryption status and plaintext passwords when available
    """
    await ctx.info(f"Decrypting Chromium logins from: {profile_path}")
    return await chromium_decrypt_logins(
        profile_path,
        local_state_path=local_state_path,
        master_key_b64=master_key_b64,
        origin_url=origin_url,
        username_value=username_value,
        limit=limit,
    )


# ==================== Cache Management Tools ====================


@mcp.tool()
async def get_cache_stats(ctx: Context) -> dict:
    """
    Get cache statistics.

    Returns:
        JSON object with cache stats including size and entry count
    """
    await ctx.info("Getting cache statistics")
    return await cache.get_stats()


@mcp.tool()
async def clear_cache(ctx: Context) -> dict:
    """
    Clear all cache entries.

    Returns:
        JSON object with operation status
    """
    await ctx.info("Clearing cache")
    await cache.clear()
    return {"status": "success", "message": "Cache cleared"}


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
