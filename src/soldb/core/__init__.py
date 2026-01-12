"""
Core module for soldb.

This module contains the main business logic for transaction tracing and debugging:
- TransactionTracer: Traces EVM transactions
- EVMDebugger: Interactive debugger REPL
- TraceSerializer: Serializes traces to JSON format
- AutoDeployDebugger: Automated deployment and debugging
"""

from .transaction_tracer import (
    TransactionTracer,
    TransactionTrace,
    TraceStep,
    FunctionCall,
    StackVariable,
)
from .serializer import TraceSerializer
from .evm_repl import EVMDebugger
from .auto_deploy import AutoDeployDebugger

__all__ = [
    'TransactionTracer',
    'TransactionTrace',
    'TraceStep',
    'FunctionCall',
    'StackVariable',
    'TraceSerializer',
    'EVMDebugger',
    'AutoDeployDebugger',
]
