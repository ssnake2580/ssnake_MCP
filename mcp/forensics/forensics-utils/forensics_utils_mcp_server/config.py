"""Configuration for the Forensics MCP Server."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# VirusTotal API Configuration
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_API_KEY_HERE")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Cache Configuration (in-memory, LRU-evicted)
CACHE_MAX_SIZE_MB = 200  # 200MB limit

# Queue Configuration
QUEUE_RATE_LIMIT = 4  # requests per minute
QUEUE_TIMEOUT_SECONDS = 60
QUEUE_RETRY_ATTEMPTS = 3
QUEUE_RETRY_DELAY_SECONDS = 15

# File Upload Configuration
VT_MAX_FILE_SIZE_MB = 32  # VirusTotal free tier limit
VT_MAX_FILE_SIZE_BYTES = VT_MAX_FILE_SIZE_MB * 1024 * 1024

# DIE Configuration
DIE_COMMAND = "diec"  # Assumes 'diec' is in PATH (CLI version)

# ExifTool Configuration
EXIFTOOL_COMMAND = "exiftool"  # Assumes 'exiftool' is in PATH

# Server Configuration
SERVER_NAME = "forensics-utils-mcp-server"
SERVER_VERSION = "1.0.0"
