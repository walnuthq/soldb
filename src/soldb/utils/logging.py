"""
Logging configuration for soldb.

This module provides a centralized logging setup with colored output
for console and optional file logging.
"""

import logging
import sys
from typing import Optional

from soldb.colors import Colors

# Custom log level for very detailed tracing
TRACE = 5
logging.addLevelName(TRACE, 'TRACE')


class ColoredFormatter(logging.Formatter):
    """
    Formatter that adds ANSI colors to log levels.
    
    Colors are only applied if the output stream supports them.
    """
    
    LEVEL_COLORS = {
        TRACE: Colors.DIM,
        logging.DEBUG: Colors.DIM,
        logging.INFO: Colors.BRIGHT_CYAN,
        logging.WARNING: Colors.BRIGHT_YELLOW,
        logging.ERROR: Colors.BRIGHT_RED,
        logging.CRITICAL: Colors.BOLD + Colors.BRIGHT_RED,
    }
    
    def __init__(self, fmt: str = None, datefmt: str = None, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.LEVEL_COLORS.get(record.levelno, '')
            reset = Colors.RESET if color else ''
            record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


class SoldbLogger(logging.Logger):
    """
    Extended logger with trace level support.
    """
    
    def trace(self, msg, *args, **kwargs):
        """Log a message with TRACE level."""
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)


# Set the custom logger class
logging.setLoggerClass(SoldbLogger)


def setup_logging(
    level: int = logging.INFO,
    quiet: bool = False,
    debug: bool = False,
    verbose: bool = False,
    log_file: Optional[str] = None,
    use_colors: bool = True
) -> logging.Logger:
    """
    Configure logging for soldb.
    
    Args:
        level: Base logging level
        quiet: If True, suppress all console output
        debug: If True, set level to DEBUG
        verbose: If True, set level to TRACE (more detailed than DEBUG)
        log_file: Optional path to log file
        use_colors: Whether to use colored output
        
    Returns:
        Configured logger instance
    """
    # Determine effective level
    if verbose:
        effective_level = TRACE
    elif debug:
        effective_level = logging.DEBUG
    else:
        effective_level = level
    
    # Get or create logger
    logger = logging.getLogger('soldb')
    logger.setLevel(effective_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    if not quiet:
        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(effective_level)
        
        # Check if colors should be used
        supports_color = (
            hasattr(sys.stderr, 'isatty') and 
            sys.stderr.isatty() and
            use_colors
        )
        
        console_formatter = ColoredFormatter(
            fmt='%(levelname)s: %(message)s',
            use_colors=supports_color
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    if log_file:
        # File handler (no colors)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Optional name for the logger. If None, returns the root soldb logger.
              If provided, returns a child logger (e.g., 'soldb.tracer').
              
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f'soldb.{name}')
    return logging.getLogger('soldb')


# Global logger instance for convenient access
logger = get_logger()


# Convenience functions for logging without importing the logger
def log_debug(msg: str, *args, **kwargs):
    """Log a DEBUG message."""
    logger.debug(msg, *args, **kwargs)


def log_info(msg: str, *args, **kwargs):
    """Log an INFO message."""
    logger.info(msg, *args, **kwargs)


def log_warning(msg: str, *args, **kwargs):
    """Log a WARNING message."""
    logger.warning(msg, *args, **kwargs)


def log_error(msg: str, *args, **kwargs):
    """Log an ERROR message."""
    logger.error(msg, *args, **kwargs)


def log_trace(msg: str, *args, **kwargs):
    """Log a TRACE message (more detailed than DEBUG)."""
    if hasattr(logger, 'trace'):
        logger.trace(msg, *args, **kwargs)
    else:
        logger.log(TRACE, msg, *args, **kwargs)
