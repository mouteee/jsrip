"""
Simple logging utility for jsrip.
Provides file and console logging with optional verbosity.
"""

import logging
import sys
from pathlib import Path


class Logger:
    """Logger for jsrip with file and console output."""

    def __init__(self, output_dir, verbose=False):
        """
        Initialize logger.

        Args:
            output_dir: Directory to save log file
            verbose: Enable verbose logging (DEBUG level)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose

        # Set up logger
        self.logger = logging.getLogger('jsrip')
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # Remove existing handlers to avoid duplicates
        self.logger.handlers = []

        # Create formatters
        detailed_format = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        simple_format = logging.Formatter('%(levelname)s: %(message)s')

        # File handler - always detailed
        log_file = self.output_dir / 'jsrip.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_format)
        self.logger.addHandler(file_handler)

        # Console handler - simple output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(simple_format)
        self.logger.addHandler(console_handler)

    def info(self, message):
        """Log info level message."""
        self.logger.info(message)

    def warning(self, message):
        """Log warning level message."""
        self.logger.warning(message)

    def error(self, message):
        """Log error level message."""
        self.logger.error(message)

    def debug(self, message):
        """Log debug level message."""
        self.logger.debug(message)


def setup_logger(output_dir, verbose=False):
    """
    Create and return a logger instance.

    Args:
        output_dir: Directory to save log file
        verbose: Enable verbose logging (DEBUG level)

    Returns:
        Logger instance
    """
    return Logger(output_dir, verbose)