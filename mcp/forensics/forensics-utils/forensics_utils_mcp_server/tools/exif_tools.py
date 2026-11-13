"""EXIF metadata extraction tools."""

import os
import subprocess
import json
from typing import Any, Dict

from forensics_utils_mcp_server.config import EXIFTOOL_COMMAND
from forensics_utils_mcp_server.exceptions import ToolNotFoundError, validate_local_file_path


async def extract_exif(file_path: str) -> dict:
    """
    Extract EXIF and metadata from a file using ExifTool.

    Supports images, documents, media files, and many other formats.
    Extracts: camera info, GPS coordinates, timestamps, software versions,
    author information, and hundreds of other metadata fields.

    Args:
        file_path: Path to the file

    Returns:
        JSON object containing all metadata fields:
        {
            "status": "success",
            "file_path": "/path/to/file",
            "metadata": {
                "FileType": "JPEG",
                "MIMEType": "image/jpeg",
                "Make": "Canon",
                "Model": "EOS 5D",
                "DateTimeOriginal": "2024:01:15 14:30:00",
                "GPSLatitude": "40.7128 N",
                "GPSLongitude": "74.0060 W",
                ...
            }
        }

    Note:
        Requires ExifTool to be installed and available in PATH.
        Install: https://exiftool.org/install.html
    """
    if err := validate_local_file_path(file_path):
        return err

    # Check if ExifTool is available
    if not _is_tool_available(EXIFTOOL_COMMAND):
        return ToolNotFoundError(
            EXIFTOOL_COMMAND, "Download from: https://exiftool.org/install.html"
        ).to_dict()

    try:
        # Run ExifTool with JSON output
        result = subprocess.run(
            [EXIFTOOL_COMMAND, "-json", "-struct", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "error_type": "exiftool_failed",
                "message": f"ExifTool failed: {result.stderr}",
                "return_code": result.returncode,
            }

        # Parse JSON output
        try:
            metadata_list = json.loads(result.stdout)
            if metadata_list and len(metadata_list) > 0:
                metadata = metadata_list[0]

                # Remove SourceFile as it's redundant
                metadata.pop("SourceFile", None)

                return {
                    "status": "success",
                    "file_path": file_path,
                    "metadata": metadata,
                }
            else:
                return {
                    "status": "success",
                    "file_path": file_path,
                    "metadata": {},
                    "message": "No metadata found",
                }

        except json.JSONDecodeError as e:
            return {
                "status": "error",
                "error_type": "json_parse_error",
                "message": f"Failed to parse ExifTool output: {str(e)}",
                "raw_output": result.stdout[:1000],  # First 1000 chars
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": "ExifTool timed out after 30 seconds",
        }
    except Exception as e:
        return {"status": "error", "error_type": "unexpected_error", "message": str(e)}


def _is_tool_available(command: str) -> bool:
    """Check if a command is available in PATH."""
    try:
        subprocess.run([command, "-ver"], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
