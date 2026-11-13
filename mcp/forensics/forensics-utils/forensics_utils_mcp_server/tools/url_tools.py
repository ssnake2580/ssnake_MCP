"""URL analysis tools for VirusTotal."""

from forensics_utils_mcp_server.exceptions import VirusTotalError
from forensics_utils_mcp_server.vt_client import vt_client


async def vt_scan_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal for scanning.

    Args:
        url: The URL to scan (e.g., "http://example.com")

    Returns:
        JSON object containing scan submission results or existing analysis
    """
    try:
        return await vt_client.scan_url(url)
    except VirusTotalError as e:
        return e.to_dict()


async def vt_get_url_report(url: str) -> dict:
    """
    Get VirusTotal analysis report for a URL.

    Args:
        url: The URL to get the report for

    Returns:
        JSON object containing URL analysis report
    """
    try:
        return await vt_client.get_url_report(url)
    except VirusTotalError as e:
        return e.to_dict()
