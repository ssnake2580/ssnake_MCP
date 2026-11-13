"""String extraction tools."""

import os
import re
import string
from typing import List, Set

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.exceptions import validate_local_file_path


async def extract_strings(file_path: str, min_length: int = 4) -> dict:
    """
    Extract readable strings from a binary file.

    Useful for analyzing malware, finding embedded URLs, file paths,
    error messages, and other interesting artifacts.

    Results are cached to avoid re-processing the same file.

    Args:
        file_path: Path to the file
        min_length: Minimum string length to include (default: 4)

    Returns:
        JSON object containing extracted strings:
        {
            "status": "success",
            "file_path": "/path/to/file",
            "statistics": {
                "total_strings": 1234,
                "ascii_strings": 1000,
                "unicode_strings": 234
            },
            "strings": {
                "ascii": ["Hello World", "example.com", ...],
                "unicode": ["Wide String", ...],
                "interesting": ["http://malware.com", "C:\\Users\\Admin", ...]
            },
            "cached": false
        }
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check cache first
    cache_key = f"strings:{file_path}:{min_length}"
    cached = await cache.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract ASCII strings
        ascii_strings = _extract_ascii_strings(data, min_length)

        # Extract Unicode strings
        unicode_strings = _extract_unicode_strings(data, min_length)

        # Find interesting strings (URLs, paths, etc.)
        interesting = _find_interesting_strings(ascii_strings + unicode_strings)

        result = {
            "status": "success",
            "file_path": file_path,
            "statistics": {
                "total_strings": len(ascii_strings) + len(unicode_strings),
                "ascii_strings": len(ascii_strings),
                "unicode_strings": len(unicode_strings),
                "interesting_strings": len(interesting),
            },
            "strings": {
                "ascii": ascii_strings[:1000],  # Limit to first 1000
                "unicode": unicode_strings[:1000],
                "interesting": interesting[:500],
            },
            "truncated": len(ascii_strings) > 1000 or len(unicode_strings) > 1000,
            "cached": False,
        }

        # Save to cache
        await cache.set(cache_key, result)

        return result

    except Exception as e:
        return {
            "status": "error",
            "error_type": "string_extraction_failed",
            "message": str(e),
        }


def _extract_ascii_strings(data: bytes, min_length: int) -> List[str]:
    """Extract ASCII strings from binary data."""
    strings = []
    current = []

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    # Don't forget the last string
    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def _extract_unicode_strings(data: bytes, min_length: int) -> List[str]:
    """Extract UTF-16LE strings from binary data."""
    strings = []
    current = []
    i = 0

    while i < len(data) - 1:
        # Check for UTF-16LE pattern (ASCII char + null byte)
        if 32 <= data[i] <= 126 and data[i + 1] == 0:
            current.append(chr(data[i]))
            i += 2
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
            i += 1

    # Don't forget the last string
    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def _find_interesting_strings(strings: List[str]) -> List[str]:
    """Find interesting strings (URLs, IPs, paths, etc.)."""
    interesting: Set[str] = set()

    # Patterns
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`[\]]+', re.IGNORECASE)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    path_pattern = re.compile(r'(?:[A-Za-z]:)?\\[^<>"|?*\n]+', re.IGNORECASE)
    registry_pattern = re.compile(r"HKEY_[A-Z_]+\\[^\s]+", re.IGNORECASE)

    for s in strings:
        # URLs
        if url_pattern.search(s):
            interesting.add(s)
        # IP addresses
        elif ip_pattern.search(s):
            interesting.add(s)
        # Email addresses
        elif email_pattern.search(s):
            interesting.add(s)
        # Windows paths
        elif path_pattern.search(s):
            interesting.add(s)
        # Registry keys
        elif registry_pattern.search(s):
            interesting.add(s)
        # Base64-like strings (potential encoded data)
        elif re.match(r"^[A-Za-z0-9+/]{40,}={0,2}$", s):
            interesting.add(s)

    return sorted(list(interesting))
