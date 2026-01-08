"""
Common utilities for CLI commands.

This module provides shared functionality used across multiple CLI commands
to reduce code duplication and ensure consistent behavior.
"""

import sys
from pathlib import Path
from typing import List, Optional, Tuple, Any

from eth_utils import to_checksum_address
from eth_utils.address import is_address

from soldb.transaction_tracer import TransactionTracer
from soldb.multi_contract_ethdebug_parser import MultiContractETHDebugParser
from soldb.ethdebug_dir_parser import ETHDebugDirParser, ETHDebugSpec
from soldb.utils.exceptions import (
    SoldbError, 
    RPCConnectionError, 
    ETHDebugError,
    format_error,
    format_error_json
)
from soldb.utils.logging import logger
from soldb.colors import error, info, warning


def create_tracer(rpc_url: str, quiet_mode: bool = False) -> TransactionTracer:
    """
    Create and return a TransactionTracer instance.
    
    Args:
        rpc_url: RPC endpoint URL
        quiet_mode: If True, suppress informational output
        
    Returns:
        Configured TransactionTracer instance
        
    Raises:
        RPCConnectionError: If connection to RPC fails
    """
    logger.debug(f"Connecting to RPC: {rpc_url}")
    try:
        return TransactionTracer(rpc_url, quiet_mode=quiet_mode)
    except Exception as e:
        raise RPCConnectionError(f"Failed to connect to RPC: {e}", rpc_url=rpc_url)


def normalize_address(address: str) -> str:
    """
    Normalize an Ethereum address to checksum format.
    
    Args:
        address: Ethereum address (with or without 0x prefix)
        
    Returns:
        Checksummed address
        
    Raises:
        ValueError: If address is invalid
    """
    if not address:
        raise ValueError("Address cannot be empty")
    
    if not address.startswith('0x'):
        address = '0x' + address
    
    if not is_address(address):
        raise ValueError(f"Invalid Ethereum address: {address}")
    
    return to_checksum_address(address)


def get_ethdebug_dirs(args: Any) -> List[str]:
    """
    Extract ETHDebug directories from command arguments.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        List of ETHDebug directory paths
    """
    if hasattr(args, 'ethdebug_dir') and args.ethdebug_dir:
        if isinstance(args.ethdebug_dir, list):
            return args.ethdebug_dir
        return [args.ethdebug_dir]
    return []


def is_multi_contract_mode(args: Any) -> bool:
    """
    Check if multi-contract mode is enabled based on arguments.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        True if multi-contract mode should be used
    """
    ethdebug_dirs = get_ethdebug_dirs(args)
    return (
        getattr(args, 'multi_contract', False) or 
        len(ethdebug_dirs) > 1 or 
        getattr(args, 'contracts', None) is not None
    )


def load_multi_contract_parser(
    ethdebug_dirs: List[str],
    contracts_file: Optional[str] = None,
    json_mode: bool = False
) -> Tuple[MultiContractETHDebugParser, List[str]]:
    """
    Load multi-contract parser from ETHDebug directories.
    
    Args:
        ethdebug_dirs: List of ETHDebug directory specifications
        contracts_file: Optional path to contracts mapping file
        json_mode: If True, format errors as JSON
        
    Returns:
        Tuple of (parser, list of error messages)
    """
    multi_parser = MultiContractETHDebugParser()
    errors = []
    
    # Load from contracts mapping file if provided
    if contracts_file:
        try:
            multi_parser.load_from_mapping_file(contracts_file)
            logger.debug(f"Loaded contracts from mapping file: {contracts_file}")
        except Exception as e:
            errors.append(f"Error loading contracts mapping file: {e}")
            return multi_parser, errors
    
    # Load from ETHDebug directories
    if ethdebug_dirs:
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
            
            for spec in specs:
                try:
                    _load_contract_from_spec(multi_parser, spec)
                except FileNotFoundError as e:
                    contract_name = spec.name or spec.address or "unknown"
                    error_msg = str(e)
                    # Try to extract compiler version from the error message or debug directory
                    from soldb.ethdebug_parser import ETHDebugParser
                    try:
                        compiler_info = ETHDebugParser._get_compiler_info(spec.path)
                        if compiler_info and compiler_info not in error_msg:
                            error_msg += f" (compiler: {compiler_info})"
                    except Exception:
                        pass
                    errors.append(f"Error loading contract {contract_name}: {error_msg}")
                except Exception as e:
                    contract_name = spec.name or spec.address or "unknown"
                    errors.append(f"Unexpected error loading contract {contract_name}: {e}")
                    
        except ValueError as e:
            errors.append(f"Error parsing ETHDebug directories: {e}")
    
    return multi_parser, errors


def _load_contract_from_spec(
    multi_parser: MultiContractETHDebugParser, 
    spec: ETHDebugSpec
) -> None:
    """
    Load a contract into the multi-contract parser from a spec.
    
    Args:
        multi_parser: The parser to load into
        spec: ETHDebug specification
    """
    if spec.address and spec.name:
        # Single contract format: address:name:path
        multi_parser.load_contract(spec.address, spec.path, spec.name)
        logger.debug(f"Loaded contract {spec.name} at {spec.address}")
    elif spec.address:
        # Multi-contract format: address:path
        multi_parser.load_contract(spec.address, spec.path)
        logger.debug(f"Loaded contract at {spec.address}")
    else:
        # Just path - try to load from deployment.json
        deployment_file = Path(spec.path) / "deployment.json"
        if deployment_file.exists():
            multi_parser.load_from_deployment(deployment_file)
            logger.debug(f"Loaded contracts from deployment: {deployment_file}")
        else:
            logger.warning(f"No deployment.json found in {spec.path}, skipping...")


def load_abi_files(
    tracer: TransactionTracer, 
    multi_parser: MultiContractETHDebugParser
) -> None:
    """
    Load ABI files for all contracts in the multi-contract parser.
    
    Args:
        tracer: Transaction tracer to load ABIs into
        multi_parser: Multi-contract parser with loaded contracts
    """
    for addr, contract_info in multi_parser.contracts.items():
        abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
        if abi_path.exists():
            tracer.load_abi(str(abi_path))
            logger.debug(f"Loaded ABI for {contract_info.name} from {abi_path}")
        else:
            # Try .json extension
            json_abi_path = contract_info.debug_dir / f"{contract_info.name}.json"
            if json_abi_path.exists():
                tracer.load_abi(str(json_abi_path))
                logger.debug(f"Loaded ABI for {contract_info.name} from {json_abi_path}")


def handle_command_error(
    e: Exception, 
    json_mode: bool = False,
    exit_code: int = 1
) -> int:
    """
    Handle command errors uniformly.
    
    Args:
        e: The exception that occurred
        json_mode: If True, output as JSON
        exit_code: Exit code to return
        
    Returns:
        Exit code
    """
    error_output = format_error(e, json_mode)
    if json_mode:
        print(error_output)
    else:
        print(error_output, file=sys.stderr)
    return exit_code


def print_connection_info(rpc_url: str, json_mode: bool = False) -> None:
    """
    Print RPC connection information.
    
    Args:
        rpc_url: RPC endpoint URL
        json_mode: If True, skip output (JSON mode handles differently)
    """
    if not json_mode:
        print(f"Connecting to RPC: {info(rpc_url)}")


def validate_contract_address(
    address: str, 
    tracer: TransactionTracer,
    json_mode: bool = False
) -> bool:
    """
    Validate that a contract exists at the given address.
    
    Args:
        address: Contract address to check
        tracer: Transaction tracer for checking
        json_mode: If True, format errors as JSON
        
    Returns:
        True if valid, False otherwise (and prints error)
    """
    if not is_address(address):
        msg = f"Invalid contract address: {address}"
        if json_mode:
            print(format_error_json(msg, "InvalidAddress"))
        else:
            print(error(msg))
        return False
    
    if not tracer.is_contract_deployed(address):
        msg = f"No contract found at address: {address}"
        if json_mode:
            print(format_error_json(msg, "ContractNotFound", address=address))
        else:
            print(error(msg))
            print("Please verify:")
            print("  - The address is correct")
            print("  - You're connected to the right network")
            print("  - The contract is deployed")
        return False
    
    return True


def parse_value_arg(value_str: str, w3) -> int:
    """
    Parse a value argument (wei or ether).
    
    Args:
        value_str: Value string (e.g., "1000000000000000" or "0.001ether")
        w3: Web3 instance for conversion
        
    Returns:
        Value in wei
        
    Raises:
        ValueError: If value is invalid
    """
    if not value_str:
        return 0
    
    try:
        if isinstance(value_str, str) and value_str.endswith('ether'):
            value = value_str.split('ether')[0]
            return w3.to_wei(float(value), 'ether')
        else:
            return int(value_str)
    except Exception as e:
        raise ValueError(f"Invalid value: {value_str}. Error: {e}")


def find_debug_file(contract_addr: str) -> Optional[str]:
    """
    Try to find debug file for a contract.
    
    Note: Legacy .zasm file support is deprecated.
    This function primarily looks for ETHDebug directories.
    
    Args:
        contract_addr: Contract address to find debug info for
        
    Returns:
        Path to debug file if found, None otherwise
    """
    debug_dir = Path("debug")
    if debug_dir.exists():
        deployment_file = debug_dir / "deployment.json"
        if deployment_file.exists():
            try:
                import json
                with open(deployment_file) as f:
                    deployment = json.load(f)
                    if deployment.get('address', '').lower() == contract_addr.lower():
                        # Legacy .zasm support - deprecated
                        for zasm_file in debug_dir.glob("*.runtime.zasm"):
                            logger.warning("Using legacy .zasm debug file format. Consider migrating to ETHDebug.")
                            return str(zasm_file)
            except Exception:
                pass
    
    # Legacy fallback - look for any .zasm file
    for zasm_file in Path(".").glob("**/*.runtime.zasm"):
        logger.warning("Using legacy .zasm debug file format. Consider migrating to ETHDebug.")
        return str(zasm_file)
    
    return None
