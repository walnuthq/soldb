"""
Utilities module for soldb.

Provides common utilities, exception handling, and logging configuration.
"""

from .exceptions import (
    SoldbError,
    CompilerError,
    ETHDebugError,
    RPCConnectionError,
    TransactionError,
    ContractNotFoundError,
    InsufficientFundsError,
    format_error,
    format_error_json,
    format_exception_message,
)
from .logging import setup_logging, get_logger, logger

__all__ = [
    # Exceptions
    'SoldbError',
    'CompilerError',
    'ETHDebugError',
    'RPCConnectionError',
    'TransactionError',
    'ContractNotFoundError',
    'InsufficientFundsError',
    # Formatting
    'format_error',
    'format_error_json',
    'format_exception_message',
    # Logging
    'setup_logging',
    'get_logger',
    'logger',
]
