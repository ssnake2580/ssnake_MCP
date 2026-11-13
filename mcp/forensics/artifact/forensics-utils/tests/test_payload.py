"""Test script for forensics tools with payload.exe."""

import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from forensics_utils_mcp_server.tools.hash_tools import calculate_hashes
from forensics_utils_mcp_server.tools.string_tools import extract_strings
from forensics_utils_mcp_server.tools.die_tools import die_analyze_file
from forensics_utils_mcp_server.tools.binwalk_tools import binwalk_scan, binwalk_extract
from forensics_utils_mcp_server.tools.exif_tools import extract_exif


def test_payload_hashes():
    """Test hash calculation on payload.exe."""
    payload_path = project_root / "payload.exe"
    if not payload_path.exists():
        print(f"[SKIP] payload.exe not found at {payload_path}")
        return
    print(f"\n=== Testing hash calculation on {payload_path.name} ===")
    result = asyncio.run(calculate_hashes(str(payload_path)))
    if result["status"] == "success":
        print(f"  MD5:    {result['hashes'].get('md5')}")
        print(f"  SHA1:   {result['hashes'].get('sha1')}")
        print(f"  SHA256: {result['hashes'].get('sha256')}")
    else:
        print(f"  [ERROR] {result}")


def test_payload_strings():
    """Test string extraction on payload.exe."""
    payload_path = project_root / "payload.exe"
    if not payload_path.exists():
        print(f"[SKIP] payload.exe not found at {payload_path}")
        return
    print(f"\n=== Testing string extraction on {payload_path.name} ===")
    result = asyncio.run(extract_strings(str(payload_path), min_length=6))
    if result["status"] == "success":
        print(f"  Total strings: {result['statistics']['total_strings']}")
        print(f"  Interesting:   {result['statistics']['interesting_strings']}")
        print(f"  Sample URL:    {result['strings']['interesting'][:3]}")
    else:
        print(f"  [ERROR] {result}")


def test_payload_binwalk_scan():
    """Test binwalk scan on payload.exe."""
    payload_path = project_root / "payload.exe"
    if not payload_path.exists():
        print(f"[SKIP] payload.exe not found at {payload_path}")
        return
    print(f"\n=== Testing binwalk scan on {payload_path.name} ===")
    result = asyncio.run(binwalk_scan(str(payload_path)))
    print(f"  status={result.get('status')} signatures={result.get('total_found')}")


if __name__ == "__main__":
    test_payload_hashes()
    test_payload_strings()
    test_payload_binwalk_scan()
