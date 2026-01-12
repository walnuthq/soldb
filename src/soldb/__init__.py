"""
SolDB - Ethereum Transaction Debugger
"""

__version__ = "0.1.0"

# Main entry point
from .cli.main import main

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

# Compiler
from .compiler import (
    CompilerConfig,
    CompilationError,
    dual_compile,
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
    # Compiler
    'CompilerConfig',
    'CompilationError',
    'dual_compile',
    # Utils
    'Colors',
    'error', 'warning', 'info', 'success',
    'SoldbError',
    'RPCConnectionError',
]
