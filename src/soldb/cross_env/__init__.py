"""
Cross-Environment Debugging Bridge

This module provides the protocol and server for cross-environment debugging
between SolDB (Solidity/EVM) and StylusDB (Rust/Stylus).
"""

from .protocol import (
    CrossEnvCall,
    CrossEnvTrace,
    TraceRequest,
    TraceResponse,
    ContractInfo,
    Environment,
    PROTOCOL_VERSION,
)

__all__ = [
    "CrossEnvCall",
    "CrossEnvTrace",
    "TraceRequest",
    "TraceResponse",
    "ContractInfo",
    "Environment",
    "PROTOCOL_VERSION",
]
