"""Domain and IP analysis tools for VirusTotal."""

from forensics_utils_mcp_server.exceptions import VirusTotalError
from forensics_utils_mcp_server.vt_client import vt_client


async def vt_get_domain_report(domain: str) -> dict:
    """
    Get VirusTotal intelligence report for a domain.

    Includes: WHOIS data, DNS records, SSL certificates, reputation score,
    and related files/URLs.

    Args:
        domain: The domain name (e.g., "example.com")

    Returns:
        JSON object containing domain intelligence report
    """
    try:
        return await vt_client.get_domain_report(domain)
    except VirusTotalError as e:
        return e.to_dict()


async def vt_get_ip_report(ip: str) -> dict:
    """
    Get VirusTotal intelligence report for an IP address.

    Includes: Geolocation, ASN information, reputation score,
    related files, URLs, and domains.

    Args:
        ip: The IP address (e.g., "8.8.8.8")

    Returns:
        JSON object containing IP reputation report
    """
    try:
        return await vt_client.get_ip_report(ip)
    except VirusTotalError as e:
        return e.to_dict()
