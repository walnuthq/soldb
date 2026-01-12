"""
Compiler module for soldb.

This module provides Solidity compilation with ETHDebug support.
"""

from .config import (
    CompilerConfig,
    CompilationError,
    dual_compile,
)
from .ethdebug import (
    main as compile_main,
    compile_ethdebug_run,
)

__all__ = [
    'CompilerConfig',
    'CompilationError',
    'dual_compile',
    'compile_main',
    'compile_ethdebug_run',
]
