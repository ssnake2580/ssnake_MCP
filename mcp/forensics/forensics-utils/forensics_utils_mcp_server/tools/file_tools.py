"""File analysis tools for VirusTotal."""

import hashlib
import os
from typing import Any

from forensics_utils_mcp_server.config import VT_MAX_FILE_SIZE_BYTES
from forensics_utils_mcp_server.exceptions import FileTooLargeError, VirusTotalError, validate_local_file_path
from forensics_utils_mcp_server.vt_client import vt_client


async def vt_scan_file(file_path: str) -> dict:
    """
    Scan a file using VirusTotal.

    For files smaller than 32MB, uploads the file directly.
    For larger files, calculates hash and checks VirusTotal database.

    Args:
        file_path: Path to the file to scan

    Returns:
        JSON object containing scan results or hash lookup results
    """
    if err := validate_local_file_path(file_path):
        return err

    file_size = os.path.getsize(file_path)

    if file_size > VT_MAX_FILE_SIZE_BYTES:
        # File too large, only check by hash
        sha256_hash = _calculate_sha256_sync(file_path)
        try:
            result = await vt_client.get_file_report(sha256_hash)
            return {
                "status": "hash_lookup_only",
                "reason": "file_too_large",
                "file_size_bytes": file_size,
                "max_size_bytes": VT_MAX_FILE_SIZE_BYTES,
                "sha256": sha256_hash,
                "data": result,
            }
        except VirusTotalError as e:
            return e.to_dict()
    else:
        # Upload file for scanning
        try:
            return await vt_client.scan_file(file_path)
        except VirusTotalError as e:
            return e.to_dict()


async def vt_get_file_report(file_hash: str) -> dict:
    """
    Get VirusTotal analysis report for a file by its hash.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash of the file

    Returns:
        JSON object containing the file analysis report
    """
    try:
        return await vt_client.get_file_report(file_hash)
    except VirusTotalError as e:
        return e.to_dict()


async def vt_get_file_behavior(file_hash: str) -> dict:
    """
    Get behavior summary for a file analyzed in VirusTotal's sandbox.

    Args:
        file_hash: SHA256 hash of the file

    Returns:
        JSON object containing sandbox behavior analysis
    """
    try:
        return await vt_client.get_file_behavior(file_hash)
    except VirusTotalError as e:
        return e.to_dict()


def _calculate_sha256_sync(file_path: str) -> str:
    """Calculate SHA256 hash of a file (synchronous version)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
