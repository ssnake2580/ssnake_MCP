"""Detect It Easy (DIE) integration tools."""

import json
import os
import subprocess
from pathlib import Path

from forensics_utils_mcp_server.cache import cache
from forensics_utils_mcp_server.config import DIE_COMMAND
from forensics_utils_mcp_server.exceptions import ToolNotFoundError, ForensicsError, validate_local_file_path


async def die_analyze_file(file_path: str) -> dict:
    """
    Analyze a file using Detect It Easy (DIE) with deep scan mode.

    Uses flags: -a (all types), -u (heuristic scan), --verbose, -j (JSON output)

    Args:
        file_path: Path to the file to analyze

    Returns:
        JSON object containing detailed file analysis:
        - Packer/Compiler detection
        - Entropy analysis
        - Section details
        - Import/Export tables
        - Resources info
        - Signature matches
        - Heuristic detections
        - cached: true/false

    Note:
        Requires DIE to be installed and available in PATH.
        Download from: https://github.com/horsicq/Detect-It-Easy
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check if DIE is available
    if not _is_tool_available(DIE_COMMAND):
        return ToolNotFoundError(
            DIE_COMMAND, "Download from: https://github.com/horsicq/Detect-It-Easy"
        ).to_dict()

    # Check cache first
    cache_key = f"die:{file_path}"
    cached = await cache.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    try:
        # Run DIE with all types, heuristic scan, verbose, and JSON output
        result = subprocess.run(
            [DIE_COMMAND, "-a", "-u", "--verbose", "-j", file_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "error_type": "die_scan_failed",
                "message": f"DIE scan failed: {result.stderr}",
                "return_code": result.returncode,
            }

        # Parse JSON output
        # DIE may output heuristic info before JSON, so we need to extract JSON part
        try:
            # Find JSON start (first '{' character)
            json_start = result.stdout.find("{")
            if json_start == -1:
                raise json.JSONDecodeError("No JSON found in output", result.stdout, 0)

            json_str = result.stdout[json_start:]
            die_data = json.loads(json_str)
        except json.JSONDecodeError:
            # Fallback to raw output if JSON parsing fails
            return {
                "status": "success",
                "all_types_scan": True,
                "heuristic_scan": True,
                "verbose": True,
                "raw_output": result.stdout,
                "parse_error": "Failed to parse DIE JSON output",
                "cached": False,
            }

        result = {
            "status": "success",
            "all_types_scan": True,
            "heuristic_scan": True,
            "verbose": True,
            "file_path": file_path,
            "analysis": die_data,
            "cached": False,
        }

        # Save to cache
        await cache.set(cache_key, result)

        return result

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": "DIE scan timed out after 60 seconds",
        }
    except Exception as e:
        return {"status": "error", "error_type": "unexpected_error", "message": str(e)}


def _is_tool_available(command: str) -> bool:
    """Check if a command is available in PATH.

    Tries ``--version`` first, then falls back to ``--help``. Exit code is
    ignored because some tools (e.g. DIE) print version info on stderr and
    return non-zero on ``--help``.
    """
    for probe in ("--version", "-version", "-v", "--help", "-h"):
        try:
            result = subprocess.run(
                [command, probe], capture_output=True, timeout=5
            )
            if result.stdout or result.stderr:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return False
