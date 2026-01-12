"""
List events command implementation.

This module handles listing and decoding events from transaction logs.
"""

import sys
import json
from pathlib import Path
from typing import Optional

from soldb.core.transaction_tracer import TransactionTracer
from soldb.parsers.ethdebug import MultiContractETHDebugParser, ETHDebugDirParser
from soldb.utils.colors import error
from soldb.utils.exceptions import format_error_json
from soldb.utils.logging import logger
from soldb.cli.common import (
    get_ethdebug_dirs,
    is_multi_contract_mode,
)


def list_events_command(args) -> int:
    """
    Execute the list-events command.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    json_mode = getattr(args, 'json_events', False)
    
    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except Exception as e:
        print(error(str(e)))
        return 1
    
    # Load debug info
    _load_events_debug_info(tracer, args)
    
    # Get transaction receipt
    try:
        receipt = tracer.w3.eth.get_transaction_receipt(args.tx_hash)
    except Exception as e:
        if json_mode:
            json_output = format_error_json(str(e), "TransactionReceiptError")
            print(json.dumps(json_output, indent=2))
        else:
            print(error(str(e)))
        return 1
    
    # Decode and print events
    _print_events(tracer, receipt, json_mode)
    
    return 0


def _load_events_debug_info(tracer: TransactionTracer, args) -> None:
    """Load debug information for events decoding."""
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
    """Load a contract from spec."""
    if spec.address and spec.name:
        multi_parser.load_contract(spec.address, spec.path, spec.name)
    elif spec.address:
        multi_parser.load_contract(spec.address, spec.path)
    else:
        deployment_file = Path(spec.path) / "deployment.json"
        if deployment_file.exists():
            try:
                multi_parser.load_from_deployment(deployment_file)
            except Exception as e:
                sys.stderr.write(f"Error loading deployment.json from {spec.path}: {e}\n")
                sys.exit(1)
        else:
            sys.stderr.write(f"Warning: No deployment.json found in {spec.path}, skipping...\n")


def _print_events(tracer: TransactionTracer, receipt, json_mode: bool) -> None:
    """Print decoded events from transaction."""
    from soldb.utils.helpers import print_contracts_events
    
    if json_mode:
        events_data = print_contracts_events(tracer, receipt, json_output=True)
        print(json.dumps(events_data, indent=2))
    else:
        print_contracts_events(tracer, receipt)
