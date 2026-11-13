"""Custom exceptions for the Forensics MCP Server."""

from datetime import datetime
from typing import Any, Optional


class ForensicsError(Exception):
    """Base exception for forensics tools."""

    def __init__(
        self, message: str, error_type: str = "unknown", details: Optional[dict] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert exception to dictionary format."""
        return {
            "status": "error",
            "error_type": self.error_type,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class VirusTotalError(ForensicsError):
    """Exception for VirusTotal API errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, "virustotal_api_error", details)
        self.status_code = status_code


class RateLimitError(ForensicsError):
    """Exception for rate limit exceeded."""

    def __init__(
        self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None
    ):
        super().__init__(message, "rate_limit_exceeded", {"retry_after": retry_after})
        self.retry_after = retry_after


class CacheError(ForensicsError):
    """Exception for cache operations."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, "cache_error", details)


class ToolNotFoundError(ForensicsError):
    """Exception for missing external tools."""

    def __init__(self, tool_name: str, install_instructions: Optional[str] = None):
        super().__init__(
            f"Tool '{tool_name}' not found in PATH",
            "tool_not_found",
            {"tool": tool_name, "install_instructions": install_instructions},
        )
        self.tool_name = tool_name


class FileTooLargeError(ForensicsError):
    """Exception for files exceeding size limits."""

    def __init__(self, file_path: str, file_size: int, max_size: int):
        super().__init__(
            f"File '{file_path}' exceeds maximum size limit",
            "file_too_large",
            {
                "file_path": file_path,
                "file_size_bytes": file_size,
                "max_size_bytes": max_size,
            },
        )


class HashCalculationError(ForensicsError):
    """Exception for hash calculation errors."""

    def __init__(self, file_path: str, hash_type: str, message: str):
        super().__init__(
            f"Failed to calculate {hash_type} for '{file_path}': {message}",
            "hash_calculation_error",
            {"file_path": file_path, "hash_type": hash_type},
        )


def validate_local_file_path(file_path: str) -> dict | None:
    """Light validation for local-file tools.

    Returns an error dict when the path is missing, not absolute, or
    not a regular file. Returns ``None`` when the path is acceptable.
    """
    from os import path as _path

    if not file_path or not isinstance(file_path, str):
        return {
            "status": "error",
            "error_type": "invalid_input",
            "message": "file_path must be a non-empty string",
        }
    if not _path.isabs(file_path):
        return {
            "status": "error",
            "error_type": "invalid_input",
            "message": f"file_path must be an absolute path: {file_path}",
        }
    if not _path.exists(file_path):
        return {
            "status": "error",
            "error_type": "file_not_found",
            "message": f"File not found: {file_path}",
        }
    if not _path.isfile(file_path):
        return {
            "status": "error",
            "error_type": "invalid_input",
            "message": f"Path is not a regular file: {file_path}",
        }
    return None
