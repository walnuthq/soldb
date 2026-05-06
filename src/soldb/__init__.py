"""
SolDB - Ethereum Transaction Debugger
"""

__version__ = "0.1.0"

from .rust_cli import main

__all__ = [
    '__version__',
    'main',
]
