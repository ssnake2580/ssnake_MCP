#!/usr/bin/env python3
"""MCP server for reading, writing and removing file metadata using ExifTool."""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("exiftool-mcp")

# Initialize MCP server
app = Server("exiftool-mcp")


def check_exiftool_installed() -> bool:
    """Check if exiftool is installed and available in PATH."""
    return shutil.which("exiftool") is not None


async def run_exiftool(args: list[str]) -> tuple[str, str, int]:
    """Run exiftool command and return stdout, stderr, and return code."""
    try:
        process = await asyncio.create_subprocess_exec(
            "exiftool",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            process.returncode or 0,
        )
    except FileNotFoundError:
        return "", "exiftool not found in PATH", 1


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available ExifTool tools."""
    return [
        Tool(
            name="read_metadata",
            description="Read metadata from a file using ExifTool. Supports images, videos, audio files, PDFs, and many other formats. Returns detailed metadata including EXIF, IPTC, XMP, and format-specific information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to read metadata from (absolute or relative path)",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: Specific metadata tags to extract (e.g., ['DateTimeOriginal', 'Make', 'Model']). If not specified, all metadata is returned.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="write_metadata",
            description="Write or update metadata tags in a file using ExifTool. Creates a backup by default. Can set multiple tags at once.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to write metadata to (absolute or relative path)",
                    },
                    "tags": {
                        "type": "object",
                        "description": "Metadata tags to write as key-value pairs (e.g., {'Artist': 'John Doe', 'Copyright': '2025'})",
                    },
                    "overwrite_original": {
                        "type": "boolean",
                        "description": "If true, overwrites the original file without creating a backup. Default is false (creates backup).",
                    },
                },
                "required": ["file_path", "tags"],
            },
        ),
        Tool(
            name="remove_metadata",
            description="Remove metadata from a file using ExifTool. Can remove all metadata or specific tags.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to remove metadata from (absolute or relative path)",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: Specific metadata tags to remove (e.g., ['GPS*', 'Comment']). If not specified, all metadata is removed.",
                    },
                    "overwrite_original": {
                        "type": "boolean",
                        "description": "If true, overwrites the original file without creating a backup. Default is false (creates backup).",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_supported_formats",
            description="List all file formats supported by ExifTool for metadata extraction.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls for ExifTool operations."""

    # Check if exiftool is installed
    if not check_exiftool_installed():
        return [
            TextContent(
                type="text",
                text="Error: exiftool is not installed or not found in PATH. Please install ExifTool from https://exiftool.org/",
            )
        ]

    if name == "read_metadata":
        file_path = arguments.get("file_path")
        tags = arguments.get("tags", [])

        if not file_path:
            return [TextContent(type="text", text="Error: file_path is required")]

        # Validate file exists
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return [
                TextContent(
                    type="text",
                    text=f"Error: File not found: {file_path}",
                )
            ]

        # Build exiftool command
        args = ["-json", "-a", "-G1"]

        # Add specific tags if requested
        if tags:
            for tag in tags:
                args.append(f"-{tag}")

        args.append(str(path))

        # Run exiftool
        stdout, stderr, returncode = await run_exiftool(args)

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error running exiftool: {stderr}",
                )
            ]

        try:
            # Parse JSON output
            metadata = json.loads(stdout)

            # Format output nicely
            if metadata and len(metadata) > 0:
                formatted = json.dumps(metadata[0], indent=2)
                return [
                    TextContent(
                        type="text",
                        text=f"Metadata for {path.name}:\n\n{formatted}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"No metadata found for {path.name}",
                    )
                ]
        except json.JSONDecodeError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error parsing exiftool output: {e}\n\nRaw output:\n{stdout}",
                )
            ]

    elif name == "write_metadata":
        file_path = arguments.get("file_path")
        tags = arguments.get("tags", {})
        overwrite_original = arguments.get("overwrite_original", False)

        if not file_path:
            return [TextContent(type="text", text="Error: file_path is required")]

        if not tags or not isinstance(tags, dict):
            return [
                TextContent(
                    type="text",
                    text="Error: tags must be a non-empty dictionary of key-value pairs",
                )
            ]

        # Validate file exists
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return [
                TextContent(
                    type="text",
                    text=f"Error: File not found: {file_path}",
                )
            ]

        # Build exiftool command
        args = []

        # Add overwrite option if requested
        if overwrite_original:
            args.append("-overwrite_original")

        # Add tag assignments
        for tag, value in tags.items():
            args.append(f"-{tag}={value}")

        args.append(str(path))

        # Run exiftool
        stdout, stderr, returncode = await run_exiftool(args)

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error writing metadata: {stderr}",
                )
            ]

        backup_msg = (
            "" if overwrite_original else " (backup created with _original suffix)"
        )
        return [
            TextContent(
                type="text",
                text=f"Successfully wrote metadata to {path.name}{backup_msg}\n\n{stdout}",
            )
        ]

    elif name == "remove_metadata":
        file_path = arguments.get("file_path")
        tags = arguments.get("tags", [])
        overwrite_original = arguments.get("overwrite_original", False)

        if not file_path:
            return [TextContent(type="text", text="Error: file_path is required")]

        # Validate file exists
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return [
                TextContent(
                    type="text",
                    text=f"Error: File not found: {file_path}",
                )
            ]

        # Build exiftool command
        args = []

        # Add overwrite option if requested
        if overwrite_original:
            args.append("-overwrite_original")

        # Add tag removal
        if tags:
            # Remove specific tags
            for tag in tags:
                args.append(f"-{tag}=")
        else:
            # Remove all metadata
            args.append("-all=")

        args.append(str(path))

        # Run exiftool
        stdout, stderr, returncode = await run_exiftool(args)

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error removing metadata: {stderr}",
                )
            ]

        backup_msg = (
            "" if overwrite_original else " (backup created with _original suffix)"
        )
        tags_msg = f"tags: {', '.join(tags)}" if tags else "all metadata"
        return [
            TextContent(
                type="text",
                text=f"Successfully removed {tags_msg} from {path.name}{backup_msg}\n\n{stdout}",
            )
        ]

    elif name == "list_supported_formats":
        # Run exiftool -listwf to get writable formats
        # Run exiftool -listf to get readable formats
        stdout, stderr, returncode = await run_exiftool(["-listf"])

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error running exiftool: {stderr}",
                )
            ]

        return [
            TextContent(
                type="text",
                text=f"ExifTool Supported File Formats:\n\n{stdout}",
            )
        ]

    else:
        return [
            TextContent(
                type="text",
                text=f"Error: Unknown tool: {name}",
            )
        ]


async def main():
    """Run the MCP server."""
    from mcp.server.stdio import stdio_server

    logger.info("Starting MCP ExifTool server")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
