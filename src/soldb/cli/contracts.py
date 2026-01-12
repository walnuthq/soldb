"""
List contracts command implementation.

This module handles listing all contracts involved in a transaction.
"""

import sys
import json
from pathlib import Path
from typing import Optional

from soldb.core.transaction_tracer import TransactionTracer
from soldb.parsers.ethdebug import MultiContractETHDebugParser, ETHDebugDirParser
from soldb.utils.colors import error
from soldb.utils.logging import logger
from soldb.cli.common import (
    get_ethdebug_dirs,
    is_multi_contract_mode,
    load_abi_files,
)


def list_contracts_command(args) -> int:
    """
    Execute the list-contracts command.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except Exception as e:
        print(error(str(e)))
        return 1
    
    # Load debug info
    _load_contracts_debug_info(tracer, args)
    
    # Get transaction trace
    try:
        trace = tracer.trace_transaction(args.tx_hash)
    except ValueError as e:
        print(error(str(e)))
        return 1
    
    # Print contracts involved in the transaction
    _print_contracts_in_transaction(tracer, trace)
    
    return 0


def _load_contracts_debug_info(tracer: TransactionTracer, args) -> None:
    """Load debug information for contracts listing."""
    ethdebug_dirs = get_ethdebug_dirs(args)
    multi_contract_mode = is_multi_contract_mode(args)
    
    if not multi_contract_mode:
        return
    
    multi_parser = MultiContractETHDebugParser()
    
    # Load from contracts mapping file if provided
    if getattr(args, 'contracts', None):
        try:
            multi_parser.load_from_mapping_file(args.contracts)
        except Exception as e:
            print(f"Error loading contracts mapping file: {e}")
            sys.exit(1)
    
    # Load from ethdebug directories
    if ethdebug_dirs:
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
            for spec in specs:
                _load_contract_from_spec(multi_parser, spec)
        except ValueError as e:
            sys.stderr.write(f"Error parsing ethdebug directories: {e}\n")
            sys.exit(1)
    
    # Load ABIs
    for addr, contract_info in multi_parser.contracts.items():
        abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
        if abi_path.exists():
            tracer.load_abi(str(abi_path))
        elif (contract_info.debug_dir / f"{contract_info.name}.json").exists():
            tracer.load_abi(str(contract_info.debug_dir / f"{contract_info.name}.json"))
    
    tracer.multi_contract_parser = multi_parser


def _load_contract_from_spec(multi_parser: MultiContractETHDebugParser, spec) -> None:
    """Load a contract from spec with error handling."""
    try:
        if spec.address and spec.name:
            multi_parser.load_contract(spec.address, spec.path, spec.name)
        elif spec.address:
            multi_parser.load_contract(spec.address, spec.path)
        else:
            deployment_file = Path(spec.path) / "deployment.json"
            if deployment_file.exists():
                multi_parser.load_from_deployment(deployment_file)
            else:
                sys.stderr.write(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
    except FileNotFoundError as e:
        contract_name = spec.name or spec.address or "unknown"
        error_msg = str(e)
        # Try to extract compiler version from the error message or debug directory
        from soldb.parsers.ethdebug import ETHDebugParser
        try:
            compiler_info = ETHDebugParser._get_compiler_info(spec.path)
            if compiler_info and compiler_info not in error_msg:
                error_msg += f" (compiler: {compiler_info})"
        except Exception:
            pass
        print(error(f"Error loading contract {contract_name}: {error_msg}"))
        sys.exit(1)


def _print_contracts_in_transaction(tracer: TransactionTracer, trace) -> None:
    """Print all contracts involved in a transaction."""
    from soldb.utils.helpers import print_contracts_in_transaction
    print_contracts_in_transaction(tracer, trace)
