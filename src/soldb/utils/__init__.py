"""
Utilities module for soldb.

Provides common utilities, exception handling, logging, colors, and helper functions.
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
from .colors import (
    Colors,
    SUPPORTS_COLOR,
    red, green, yellow, blue, magenta, cyan,
    bold, dim, underline,
    error, success, warning, info, highlight,
    opcode, address, number, source_line,
    stack_item, pc_value, gas_value, function_name,
    bullet_point,
)
from .helpers import (
    format_error_json as helpers_format_error_json,
    print_contracts_in_transaction,
    decode_event_log,
    print_contracts_events,
    serialize_events_to_json,
    format_exception_message as helpers_format_exception_message,
)

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
    # Colors
    'Colors',
    'SUPPORTS_COLOR',
    'red', 'green', 'yellow', 'blue', 'magenta', 'cyan',
    'bold', 'dim', 'underline',
    'error', 'success', 'warning', 'info', 'highlight',
    'opcode', 'address', 'number', 'source_line',
    'stack_item', 'pc_value', 'gas_value', 'function_name',
    'bullet_point',
    # Helpers
    'print_contracts_in_transaction',
    'decode_event_log',
    'print_contracts_events',
    'serialize_events_to_json',
]
