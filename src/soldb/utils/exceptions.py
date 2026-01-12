"""
Custom exceptions for soldb.

This module provides a hierarchy of exceptions for different error cases
in the soldb debugger, along with utilities for formatting errors consistently.
"""

import json
from typing import Any, Dict, Optional


class SoldbError(Exception):
    """
    Base exception for all soldb errors.
    
    Attributes:
        message: Human-readable error message
        details: Additional context as key-value pairs
        error_code: Optional error code for programmatic handling
    """
    
    def __init__(
        self, 
        message: str, 
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None
    ):
        self.message = message
        self.details = details or {}
        self.error_code = error_code or self.__class__.__name__
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error": True,
            "type": self.error_code,
            "message": self.message,
            **self.details
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert exception to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Connection Errors
# ============================================================================

class RPCConnectionError(SoldbError):
    """Raised when RPC connection fails."""
    
    def __init__(self, message: str, rpc_url: Optional[str] = None, **kwargs):
        details = {"rpc_url": rpc_url} if rpc_url else {}
        details.update(kwargs)
        super().__init__(message, details, "RPCConnectionError")


# ============================================================================
# Transaction Errors
# ============================================================================

class TransactionError(SoldbError):
    """Raised when transaction operations fail."""
    
    def __init__(
        self, 
        message: str, 
        tx_hash: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if tx_hash:
            details["tx_hash"] = tx_hash
        details.update(kwargs)
        super().__init__(message, details, "TransactionError")


class TransactionNotFoundError(TransactionError):
    """Raised when transaction is not found."""
    
    def __init__(self, tx_hash: str, **kwargs):
        super().__init__(
            f"Transaction not found: {tx_hash}",
            tx_hash=tx_hash,
            **kwargs
        )
        self.error_code = "TransactionNotFoundError"


class DebugTraceUnavailableError(TransactionError):
    """Raised when debug trace is not available for a transaction."""
    
    def __init__(
        self, 
        tx_hash: str, 
        reason: Optional[str] = None,
        **kwargs
    ):
        message = f"debug_traceTransaction unavailable for {tx_hash}"
        if reason:
            message += f": {reason}"
        super().__init__(message, tx_hash=tx_hash, **kwargs)
        self.error_code = "DebugTraceUnavailable"


# ============================================================================
# Contract Errors
# ============================================================================

class ContractError(SoldbError):
    """Base class for contract-related errors."""
    
    def __init__(
        self, 
        message: str, 
        contract_address: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if contract_address:
            details["contract_address"] = contract_address
        details.update(kwargs)
        super().__init__(message, details, "ContractError")


class ContractNotFoundError(ContractError):
    """Raised when contract is not found at address."""
    
    def __init__(self, address: str, **kwargs):
        super().__init__(
            f"No contract found at address: {address}",
            contract_address=address,
            **kwargs
        )
        self.error_code = "ContractNotFoundError"


class InsufficientFundsError(ContractError):
    """Raised when sender has insufficient funds."""
    
    def __init__(
        self, 
        address: str, 
        available: int, 
        required: int,
        **kwargs
    ):
        super().__init__(
            f"Insufficient funds for address {address}. "
            f"Available: {available} wei, Required: {required} wei",
            contract_address=address,
            available_balance=str(available),
            required_amount=str(required),
            **kwargs
        )
        self.error_code = "InsufficientFundsError"


# ============================================================================
# ETHDebug Errors
# ============================================================================

class ETHDebugError(SoldbError):
    """Base class for ETHDebug-related errors."""
    
    def __init__(
        self, 
        message: str, 
        debug_dir: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if debug_dir:
            details["debug_dir"] = debug_dir
        details.update(kwargs)
        super().__init__(message, details, "ETHDebugError")


class ETHDebugNotFoundError(ETHDebugError):
    """Raised when ETHDebug files are not found."""
    
    def __init__(
        self, 
        debug_dir: str, 
        compiler_version: Optional[str] = None,
        **kwargs
    ):
        message = f"ETHDebug info not found in {debug_dir}"
        if compiler_version:
            message += f" (compiled with {compiler_version})"
        details = {"compiler_version": compiler_version} if compiler_version else {}
        details.update(kwargs)
        super().__init__(message, debug_dir=debug_dir, **details)
        self.error_code = "ETHDebugNotFoundError"


class InvalidETHDebugSpecError(ETHDebugError):
    """Raised when ETHDebug specification is invalid."""
    
    def __init__(self, spec: str, reason: str, **kwargs):
        super().__init__(
            f"Invalid ETHDebug specification '{spec}': {reason}",
            spec=spec,
            reason=reason,
            **kwargs
        )
        self.error_code = "InvalidETHDebugSpecError"


# ============================================================================
# Compiler Errors
# ============================================================================

class CompilerError(SoldbError):
    """Raised when compilation fails."""
    
    def __init__(
        self, 
        message: str, 
        compiler_version: Optional[str] = None,
        **kwargs
    ):
        details = {}
        if compiler_version:
            details["compiler_version"] = compiler_version
        details.update(kwargs)
        super().__init__(message, details, "CompilerError")


class UnsupportedCompilerVersionError(CompilerError):
    """Raised when compiler version doesn't support required features."""
    
    def __init__(
        self, 
        version: str, 
        required_version: str,
        feature: str = "ETHDebug",
        **kwargs
    ):
        super().__init__(
            f"Compiler version {version} does not support {feature}. "
            f"Required: {required_version} or higher",
            compiler_version=version,
            required_version=required_version,
            feature=feature,
            **kwargs
        )
        self.error_code = "UnsupportedCompilerVersionError"


# ============================================================================
# Parsing Errors
# ============================================================================

class ParseError(SoldbError):
    """Raised when parsing fails."""
    
    def __init__(self, message: str, source: Optional[str] = None, **kwargs):
        details = {"source": source} if source else {}
        details.update(kwargs)
        super().__init__(message, details, "ParseError")


class ABIParseError(ParseError):
    """Raised when ABI parsing fails."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(message, **kwargs)
        self.error_code = "ABIParseError"


class SourceMapParseError(ParseError):
    """Raised when source map parsing fails."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(message, **kwargs)
        self.error_code = "SourceMapParseError"


# ============================================================================
# Error Formatting Utilities
# ============================================================================

def format_error(e: Exception, json_mode: bool = False) -> str:
    """
    Format an exception for display.
    
    Args:
        e: The exception to format
        json_mode: If True, output as JSON; otherwise use colored text
        
    Returns:
        Formatted error string
    """
    if isinstance(e, SoldbError):
        if json_mode:
            return e.to_json()
        else:
            from soldb.utils.colors import error
            return error(e.message)
    else:
        if json_mode:
            return json.dumps({
                "error": True,
                "type": type(e).__name__,
                "message": str(e)
            }, indent=2)
        else:
            from soldb.utils.colors import error
            return error(str(e))


def format_error_json(
    message: str, 
    error_type: str = "Error",
    **kwargs
) -> Dict[str, Any]:
    """
    Create a standardized error JSON structure.
    
    Args:
        message: Error message
        error_type: Error type/code
        **kwargs: Additional fields to include
        
    Returns:
        Dictionary suitable for JSON output
    """
    return {
        "error": True,
        "type": error_type,
        "message": message,
        **kwargs
    }


# Backwards compatibility alias
ConnectionError = RPCConnectionError


def format_exception_message(e: Exception) -> str:
    """
    Extract a clean, user-friendly error message from any exception.
    Works uniformly for all exception types.
    
    Args:
        e: Exception instance
        
    Returns:
        Clean error message string
    """
    # Web3RPCError and similar have args[0] as dict
    if hasattr(e, 'args') and e.args:
        first_arg = e.args[0]
        
        if isinstance(first_arg, dict):
            # RPC error format: {'code': -32003, 'message': '...'}
            return first_arg.get('message', str(e))
        elif isinstance(first_arg, str):
            return first_arg
        else:
            # Multiple args - use first meaningful one
            return str(first_arg)
    
    # Standard exception string representation
    return str(e)
