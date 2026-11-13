"""Tools package initialization."""

from forensics_utils_mcp_server.tools.file_tools import vt_scan_file, vt_get_file_report, vt_get_file_behavior
from forensics_utils_mcp_server.tools.url_tools import vt_scan_url, vt_get_url_report
from forensics_utils_mcp_server.tools.domain_tools import vt_get_domain_report, vt_get_ip_report
from forensics_utils_mcp_server.tools.search_tools import vt_search_files, vt_get_comments
from forensics_utils_mcp_server.tools.die_tools import die_analyze_file
from forensics_utils_mcp_server.tools.hash_tools import calculate_hashes
from forensics_utils_mcp_server.tools.exif_tools import extract_exif
from forensics_utils_mcp_server.tools.string_tools import extract_strings
from forensics_utils_mcp_server.tools.binwalk_tools import binwalk_scan, binwalk_extract
from forensics_utils_mcp_server.tools.firefox_tools import (
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
)
from forensics_utils_mcp_server.tools.chromium_tools import (
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

__all__ = [
    # VirusTotal File
    "vt_scan_file",
    "vt_get_file_report",
    "vt_get_file_behavior",
    # VirusTotal URL
    "vt_scan_url",
    "vt_get_url_report",
    # VirusTotal Domain/IP
    "vt_get_domain_report",
    "vt_get_ip_report",
    # VirusTotal Search
    "vt_search_files",
    "vt_get_comments",
    # Local Tools
    "die_analyze_file",
    "calculate_hashes",
    "extract_exif",
    "extract_strings",
    # Binwalk
    "binwalk_scan",
    "binwalk_extract",
    # Firefox Artifacts
    "firefox_profile_summary",
    "firefox_parse_history",
    "firefox_parse_bookmarks",
    "firefox_parse_downloads",
    "firefox_parse_cookies",
    "firefox_decrypt_cookies",
    "firefox_parse_sessions",
    "firefox_parse_session_storage",
    "firefox_parse_favicons",
    "firefox_parse_extensions",
    "firefox_parse_preferences",
    "firefox_parse_logins",
    "firefox_parse_web_data",
    "firefox_parse_local_storage",
    "firefox_parse_indexeddb",
    "firefox_parse_cache",
    "firefox_decrypt_logins",
    # Chromium Deep Artifacts
    "chromium_profile_summary",
    "chromium_parse_local_storage",
    "chromium_parse_session_storage",
    "chromium_parse_indexeddb",
    "chromium_parse_cache",
    "chromium_parse_history",
    "chromium_parse_downloads",
    "chromium_parse_sessions",
    "chromium_parse_favicons",
    "chromium_parse_web_data",
    "chromium_parse_extensions",
    "chromium_parse_preferences",
    "chromium_parse_bookmarks",
    "chromium_parse_logins",
    "chromium_decrypt_logins",
    "chromium_parse_cookies",
    "chromium_decrypt_cookies",
]
