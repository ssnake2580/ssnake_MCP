"""Binwalk integration tools for firmware and embedded file analysis."""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.exceptions import ToolNotFoundError, validate_local_file_path

BINWALK_COMMAND = "binwalk"


def _is_tool_available(command: str) -> bool:
    """Check if a command is available in PATH."""
    try:
        subprocess.run([command, "--version"], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _parse_signature_details(description: str) -> Dict[str, Any]:
    """
    Parse detailed information from binwalk signature description.

    Extracts: file_type, operating_system, timestamp, total_size, etc.
    """
    details = {
        "file_type": None,
        "operating_system": None,
        "timestamp": None,
        "total_size_bytes": None,
        "raw_description": description,
    }

    # Extract file type (text before first comma)
    file_type_match = re.match(r"^([^,]+)", description)
    if file_type_match:
        details["file_type"] = file_type_match.group(1).strip()

    # Extract operating system - get everything until "timestamp" or end
    os_match = re.search(
        r"operating system:\s*(.+?)(?=,\s*timestamp|$)", description, re.IGNORECASE
    )
    if os_match:
        details["operating_system"] = os_match.group(1).strip()

    # Extract timestamp
    ts_match = re.search(
        r"timestamp:\s*([\d]{4}-[\d]{2}-[\d]{2}\s+[\d]{2}:[\d]{2}:[\d]{2})", description
    )
    if ts_match:
        details["timestamp"] = ts_match.group(1)

    # Extract total size
    size_match = re.search(
        r"total size:\s*([\d,]+)\s*bytes", description, re.IGNORECASE
    )
    if size_match:
        size_str = size_match.group(1).replace(",", "")
        details["total_size_bytes"] = int(size_str)

    return details


def _parse_binwalk_output(output: str) -> List[Dict[str, Any]]:
    """
    Parse binwalk text output into structured data.

    Expected format:
    DECIMAL                            HEXADECIMAL                        DESCRIPTION
    41958049                           0x2803AA1                          gzip compressed data...
    """
    signatures = []
    lines = output.split("\n")

    # Find the header line
    header_idx = -1
    for i, line in enumerate(lines):
        if "DECIMAL" in line and "HEXADECIMAL" in line and "DESCRIPTION" in line:
            header_idx = i
            break

    if header_idx == -1:
        return signatures

    # Parse data lines
    current_sig = None
    for i in range(header_idx + 2, len(lines)):  # Skip header and separator
        line = lines[i]

        # Check for separator or end
        if "---" in line or "Analyzed" in line:
            break

        # Try to match a signature line
        # Pattern: <decimal> <whitespace> <hex> <whitespace> <description>
        match = re.match(r"^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", line)
        if match:
            # Save previous signature if exists
            if current_sig:
                signatures.append(current_sig)

            decimal = match.group(1)
            hex_val = match.group(2)
            description = match.group(3).strip()

            current_sig = {
                "offset_decimal": int(decimal),
                "offset_hex": hex_val,
                "description": description,
            }

            # Parse detailed information
            details = _parse_signature_details(description)
            current_sig.update(details)

        elif current_sig and line.strip() and not re.match(r"^\s*\d", line):
            # Continuation of description (indented) - add space only if needed
            current_sig["description"] += " " + line.strip()

    # Don't forget the last signature
    if current_sig:
        signatures.append(current_sig)

    # Now parse details for all signatures with complete descriptions
    for sig in signatures:
        details = _parse_signature_details(sig["description"])
        sig.update(details)

    return signatures


def _parse_binwalk_footer(output: str) -> Dict[str, Any]:
    """
    Parse footer statistics from binwalk output.

    Example: "Analyzed 1 file for 85 file signatures (187 magic patterns) in 576.0 milliseconds"
    """
    stats = {
        "files_analyzed": None,
        "signatures_found": None,
        "magic_patterns": None,
        "execution_time_ms": None,
    }

    # Parse main statistics
    footer_match = re.search(
        r"Analyzed (\d+) file[s]? for (\d+) file signatures \((\d+) magic patterns\) in ([\d.]+) milliseconds",
        output,
    )
    if footer_match:
        stats["files_analyzed"] = int(footer_match.group(1))
        stats["signatures_found"] = int(footer_match.group(2))
        stats["magic_patterns"] = int(footer_match.group(3))
        stats["execution_time_ms"] = float(footer_match.group(4))

    return stats


def _parse_binwalk_extract_output(output: str) -> Dict[str, Any]:
    """
    Parse binwalk extract output for detailed extraction information.

    Extracts:
    - Successful extractions with offsets and file types
    - Footer statistics from recursive scan
    - Errors if any
    """
    extract_info = {"extractions": [], "errors": [], "footer_stats": None}

    lines = output.split("\n")

    # Parse successful extractions
    # Pattern: [+] Extraction of <type> data at offset <offset> completed successfully
    for line in lines:
        success_match = re.search(
            r"\[\+\] Extraction of (\w+) data at offset (0x[0-9A-Fa-f]+) completed successfully",
            line,
        )
        if success_match:
            extract_info["extractions"].append(
                {
                    "file_type": success_match.group(1),
                    "offset_hex": success_match.group(2),
                    "status": "success",
                }
            )

        # Parse errors
        # Pattern: [-] or [!] Error messages
        error_match = re.search(r"\[-\]|\[!\]\s*(.+)", line)
        if error_match and error_match.group(1):
            extract_info["errors"].append(error_match.group(1).strip())

    # Parse footer statistics (from recursive scan)
    footer_match = re.search(
        r"Analyzed (\d+) file[s]? for (\d+) file signatures \((\d+) magic patterns\) in ([\d.]+) milliseconds",
        output,
    )
    if footer_match:
        extract_info["footer_stats"] = {
            "files_analyzed": int(footer_match.group(1)),
            "signatures_found": int(footer_match.group(2)),
            "magic_patterns": int(footer_match.group(3)),
            "execution_time_ms": float(footer_match.group(4)),
        }

    return extract_info


async def binwalk_scan(file_path: str) -> dict:
    """
    Scan a file for embedded signatures using binwalk.

    Args:
        file_path: Path to the file to analyze

    Returns:
        JSON object containing detected signatures:
        {
            "status": "success",
            "file_path": "/path/to/file",
            "signatures": [
                {
                    "offset_decimal": 41958049,
                    "offset_hex": "0x2803AA1",
                    "description": "gzip compressed data, operating system: FAT..."
                }
            ],
            "total_found": 85,
            "cached": false
        }

    Note:
        Requires binwalk to be installed.
        Install: pip install binwalk
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check cache first
    cache_key = f"binwalk_scan:{file_path}"
    cached = await cache.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    # Check if binwalk is available
    if not _is_tool_available(BINWALK_COMMAND):
        return ToolNotFoundError(
            BINWALK_COMMAND, "Install: pip install binwalk"
        ).to_dict()

    try:
        # Run binwalk with verbose output
        result = subprocess.run(
            [BINWALK_COMMAND, "-v", file_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0 and not result.stdout:
            return {
                "status": "error",
                "error_type": "binwalk_scan_failed",
                "message": f"Binwalk failed: {result.stderr}",
                "return_code": result.returncode,
            }

        # Parse the output
        signatures = _parse_binwalk_output(result.stdout)

        # Parse footer statistics
        footer_stats = _parse_binwalk_footer(result.stdout)

        # Extract statistics from footer if present
        total_found = footer_stats.get("signatures_found") or len(signatures)

        result = {
            "status": "success",
            "file_path": file_path,
            "signatures": signatures,
            "total_found": total_found,
            "statistics": footer_stats,
            "cached": False,
        }

        # Save to cache
        await cache.set(cache_key, result)

        return result

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": "Binwalk scan timed out after 120 seconds",
        }
    except Exception as e:
        return {"status": "error", "error_type": "unexpected_error", "message": str(e)}


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename for use as directory name."""
    # Replace characters that are invalid in Windows paths
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    # Remove trailing dots and spaces (Windows restriction)
    filename = filename.rstrip(". ")
    return filename


async def binwalk_extract(file_path: str, output_dir: str = None) -> dict:
    """
    Extract embedded files from a binary using binwalk.

    Args:
        file_path: Path to the file to extract from
        output_dir: Optional custom output directory (default: binwalk creates 'extractions/')

    Returns:
        JSON object containing extraction results:
        {
            "status": "success",
            "file_path": "/path/to/file",
            "extraction_dir": "extractions/<filename>/",
            "extracted_files": ["0x1000.zip", "0x2000.elf"],
            "total_extracted": 2
        }

    Note:
        Requires binwalk to be installed.
        Extracted files are saved to 'extractions/<filename>/' by default.
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check if binwalk is available
    if not _is_tool_available(BINWALK_COMMAND):
        return ToolNotFoundError(
            BINWALK_COMMAND, "Install: pip install binwalk"
        ).to_dict()

    try:
        # Honor caller-supplied output_dir; fall back to ./extractions/<filename>
        if output_dir:
            extraction_dir = Path(output_dir)
        else:
            file_stem = Path(file_path).name
            extraction_dir = Path.cwd() / "extractions" / file_stem
        extraction_dir.mkdir(parents=True, exist_ok=True)

        # Build command with custom directory
        cmd = [BINWALK_COMMAND, "-e", "-M", "-C", str(extraction_dir), file_path]

        # Run binwalk extract
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes for extraction
        )

        # Parse extraction output
        extract_info = _parse_binwalk_extract_output(result.stdout)

        # Binwalk may return non-zero but still extract files
        # Find extracted files - binwalk creates subdir with filename
        file_name = Path(file_path).name
        extracted_files = []

        # Binwalk creates: extractions/<filename>.extracted/<extracted_files>
        # Or: extractions/<filename>/<extracted_files>
        possible_dirs = [
            extraction_dir / f"{file_name}.extracted",
            extraction_dir / file_name,
        ]

        file_extraction_dir = None
        for possible_dir in possible_dirs:
            if possible_dir.exists():
                file_extraction_dir = possible_dir
                break

        if file_extraction_dir and file_extraction_dir.exists():
            # List all files recursively
            for f in file_extraction_dir.rglob("*"):
                if f.is_file():
                    # Get relative path from extraction_dir
                    rel_path = f.relative_to(extraction_dir)
                    extracted_files.append(str(rel_path))
        elif extraction_dir.exists():
            # Fallback: list files directly in extraction_dir
            extracted_files = [f.name for f in extraction_dir.iterdir() if f.is_file()]

        return {
            "status": "success",
            "file_path": file_path,
            "extraction_dir": str(extraction_dir),
            "file_extraction_subdir": str(file_extraction_dir)
            if file_extraction_dir
            else None,
            "extracted_files": extracted_files,
            "total_extracted": len(extracted_files),
            "extractions_details": extract_info["extractions"],
            "total_extractions_attempted": len(extract_info["extractions"]),
            "extraction_errors": extract_info["errors"]
            if extract_info["errors"]
            else None,
            "recursive_scan_stats": extract_info["footer_stats"],
            "raw_output": result.stdout if result.stdout else None,
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": "Binwalk extraction timed out after 300 seconds",
        }
    except Exception as e:
        return {"status": "error", "error_type": "unexpected_error", "message": str(e)}
