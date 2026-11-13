"""Search tools for VirusTotal."""

from forensics_utils_mcp_server.exceptions import VirusTotalError
from forensics_utils_mcp_server.vt_client import vt_client


async def vt_search_files(query: str, limit: int = 10) -> dict:
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
    try:
        return await vt_client.search_files(query, limit)
    except VirusTotalError as e:
        return e.to_dict()


async def vt_get_comments(object_id: str, object_type: str = "files") -> dict:
    """
    Get community comments for a VirusTotal object.

    Args:
        object_id: The ID of the object (hash for files, URL ID for URLs)
        object_type: Type of object ("files", "urls", "domains", "ip_addresses")

    Returns:
        JSON object containing community comments and votes
    """
    try:
        return await vt_client.get_comments(object_id, object_type)
    except VirusTotalError as e:
        return e.to_dict()
