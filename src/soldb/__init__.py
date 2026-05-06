"""
SolDB - Ethereum Transaction Debugger
"""

__version__ = "0.1.0"

# Main entry point
from .rust_cli import main

# Core components
from .core import (
    TransactionTracer,
    TransactionTrace,
    TraceStep,
    FunctionCall,
    TraceSerializer,
)

# Parsers
from .parsers import (
    ETHDebugParser,
    ETHDebugInfo,
    MultiContractETHDebugParser,
    SourceMapParser,
    SourceMapInfo,
)

# Utilities
from .utils import (
    Colors,
    error, warning, info, success,
    SoldbError,
    RPCConnectionError,
)

__all__ = [
    # Version
    '__version__',
    # Main
    'main',
    # Core
    'TransactionTracer',
    'TransactionTrace',
    'TraceStep',
    'FunctionCall',
    'TraceSerializer',
    # Parsers
    'ETHDebugParser',
    'ETHDebugInfo',
    'MultiContractETHDebugParser',
    'SourceMapParser',
    'SourceMapInfo',
    # Utils
    'Colors',
    'error', 'warning', 'info', 'success',
    'SoldbError',
    'RPCConnectionError',
]
