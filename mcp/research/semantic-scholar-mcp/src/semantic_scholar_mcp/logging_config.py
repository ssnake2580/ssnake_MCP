"""Centralized logging configuration for Semantic Scholar MCP."""

import logging
import sys
from typing import Literal

from semantic_scholar_mcp.config import settings

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def setup_logging(
    level: LogLevel | None = None,
    format_style: Literal["simple", "detailed"] | None = None,
) -> logging.Logger:
    """Configure logging for the application.

    Args:
        level: Log level (defaults to settings.log_level or INFO)
        format_style: "simple" for basic, "detailed" for timestamps + module
                      (defaults to settings.log_format or simple)

    Returns:
        Configured root logger for semantic_scholar_mcp
    """
    log_level = level or getattr(settings, "log_level", "INFO")
    style = format_style or getattr(settings, "log_format", "simple")

    if style == "detailed":
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    else:
        fmt = "[%(levelname)s] %(name)s: %(message)s"

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt))

    logger = logging.getLogger("semantic_scholar_mcp")
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.addHandler(handler)
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module.

    Args:
        name: Module name (use __name__)

    Returns:
        Logger instance namespaced under semantic_scholar_mcp
    """
    return logging.getLogger(f"semantic_scholar_mcp.{name}")
