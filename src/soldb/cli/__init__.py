"""
CLI module for soldb commands.

This module provides the command-line interface for soldb,
including trace, simulate, and list commands.
"""

from .main import main

__all__ = [
    'main',
    'trace_command',
    'simulate_command', 
    'list_events_command',
    'list_contracts_command',
]

# Lazy imports to avoid circular dependencies
def trace_command(args):
    """Execute the trace command."""
    from .trace import trace_command as _trace_command
    return _trace_command(args)

def simulate_command(args):
    """Execute the simulate command."""
    from .simulate import simulate_command as _simulate_command
    return _simulate_command(args)

def list_events_command(args):
    """Execute the list-events command."""
    from .events import list_events_command as _list_events_command
    return _list_events_command(args)

def list_contracts_command(args):
    """Execute the list-contracts command."""
    from .contracts import list_contracts_command as _list_contracts_command
    return _list_contracts_command(args)
