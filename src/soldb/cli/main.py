#!/usr/bin/env python3
"""
Main entry point for soldb

This module serves as the CLI entry point, handling argument parsing
and routing to the appropriate command implementations in the cli/ module.
"""

import sys
import argparse

# Import refactored CLI commands
from .trace import trace_command
from .simulate import simulate_command
from .events import list_events_command
from .contracts import list_contracts_command


def main():
    """Main entry point for soldb CLI."""
    parser = argparse.ArgumentParser(description='SolDB - Ethereum transaction analysis tool')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 0.1.0')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True

    # list-contracts command
    list_parser = subparsers.add_parser('list-contracts', help='List all contracts in the project')
    list_parser.add_argument('tx_hash', help='Transaction hash to list contracts for')
    list_parser.add_argument('--rpc-url', '-r', default='http://localhost:8545', help='RPC URL')
    list_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: [address:]path or just path')
    list_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    list_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')

    # list-events command
    event_parser = subparsers.add_parser('list-events', help='Decode and display events from transaction logs')
    event_parser.add_argument('tx_hash', help='Transaction hash to decode events from')
    event_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: address:name:path')
    event_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    event_parser.add_argument('--rpc-url', '-r', default='http://localhost:8545', help='RPC URL')
    event_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract decoding mode')
    event_parser.add_argument('--json-events', action='store_true', help='Output events in JSON format')

    # trace command
    trace_parser = subparsers.add_parser('trace', help='Trace and debug an Ethereum transaction')
    trace_parser.add_argument('tx_hash', help='Transaction hash to trace')
    trace_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: address:name:path')
    trace_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    trace_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')
    trace_parser.add_argument('--rpc', '-r', default='http://localhost:8545', help='RPC URL')
    trace_parser.add_argument('--max-steps', '-m', type=int, default=50, help='Maximum steps to show (use 0 or -1 for all steps)')
    trace_parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive debugger')
    trace_parser.add_argument('--raw', action='store_true', help='Show raw instruction trace instead of function call trace')
    trace_parser.add_argument('--json', action='store_true', help='Output trace data as JSON for web app consumption')
    
    # simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Simulate and debug an Ethereum transaction')
    simulate_parser.add_argument('--from', dest='from_addr', required=True, help='Sender address')
    simulate_parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive debugger after simulation')

    # Single positional argument that can be either contract address or contract file
    simulate_parser.add_argument('contract_address', help='Contract address (0x...)')
    simulate_parser.add_argument('function_signature', nargs='?', help='Function signature, e.g. increment(uint256)')
    simulate_parser.add_argument('function_args', nargs='*', help='Arguments for the function')
    simulate_parser.add_argument('--block', type=int, default=None, help='Block number or tag (default: latest)')
    simulate_parser.add_argument('--tx-index', type=int, default=None, help='Transaction index in block (optional)')
    simulate_parser.add_argument('--value', default=0, help='ETH value to send (in wei)')
    simulate_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: address:name:path')
    simulate_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    simulate_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')
    simulate_parser.add_argument('--rpc-url', default='http://localhost:8545', help='RPC URL')
    simulate_parser.add_argument('--json', action='store_true', help='Output trace data as JSON for web app consumption')
    simulate_parser.add_argument('--raw', action='store_true', help='Show raw instruction trace instead of function call trace')
    simulate_parser.add_argument('--max-steps', '-m', type=int, default=50, help='Maximum steps to show (use 0 or -1 for all steps)')
    simulate_parser.add_argument('--raw-data', dest='raw_data', default=None, help='Raw calldata to send (hex string, 0x...)')
    simulate_parser.add_argument('--constructor-args', nargs='*', default=[], help='Constructor arguments (only used with --contract-file)')
    simulate_parser.add_argument('--solc-path', '-solc', default='solc', help='Path to solc binary (default: solc)')
    simulate_parser.add_argument('--dual-compile', action='store_true', help='Create both optimized production and debug builds')
    simulate_parser.add_argument('--keep-build', action='store_true', help='Keep build directory after compilation (default: False)')
    simulate_parser.add_argument('--output-dir', '-o', default='./out', help='Output directory for ETHDebug files (default: ./out)')
    simulate_parser.add_argument('--production-dir', default='./build/contracts', help='Production directory for compiled contracts (default: ./build/contracts)')
    simulate_parser.add_argument('--save-config', action='store_true', help='Save configuration to walnut.config.yaml')
    simulate_parser.add_argument('--verify-version', action='store_true', help='Verify solc version supports ETHDebug and exit')
    simulate_parser.add_argument('--no-cache', action='store_true', default=False, help='Enable deployment cache')
    simulate_parser.add_argument('--cache-dir', default='.soldb_cache', help='Cache directory')
    simulate_parser.add_argument('--fork-url', help='Upstream RPC URL to fork (launch anvil)')
    simulate_parser.add_argument('--fork-block', type=int, help='Specific block number to fork')
    simulate_parser.add_argument('--fork-port', type=int, default=8545, help='Local fork port (default: 8545)')
    simulate_parser.add_argument('--keep-fork', action='store_true', help='Do not terminate the forked node on exit')
    simulate_parser.add_argument('--reuse-fork', action='store_true', help='Reuse an existing local fork if available on --fork-port')
    simulate_parser.add_argument('--no-snapshot', action='store_true', default=False, help='Disable automatic initial snapshot')
    
    args = parser.parse_args()
    
    # Route commands to refactored CLI modules
    if args.command == 'trace':
        return trace_command(args)
    elif args.command == 'simulate':
        return simulate_command(args)
    elif args.command == 'list-events':
        return list_events_command(args)
    elif args.command == 'list-contracts':
        return list_contracts_command(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
