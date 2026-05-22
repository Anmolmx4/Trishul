"""
Logger Utility
Configures colored console logging for Trishul.
"""

import logging
import sys


class ColorFormatter(logging.Formatter):
    """Custom formatter adding ANSI color codes to log levels."""

    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Configure and return the Trishul application logger.

    Args:
        verbose: If True, set log level to DEBUG; otherwise INFO

    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger("trishul")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter(
            fmt="[%(levelname)s] %(message)s"
        ))
        logger.addHandler(handler)

    return logger
