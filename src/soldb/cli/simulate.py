"""
Simulate command implementation.

This module handles simulating transactions on EVM contracts,
including call encoding, execution, and trace analysis.
"""

import sys
import os
import json
import ast
from pathlib import Path
from typing import Optional, List, Tuple, Any

from eth_utils import to_checksum_address
from eth_utils.address import is_address
from eth_abi.abi import encode
from eth_hash.auto import keccak

from soldb.core.transaction_tracer import TransactionTracer
from soldb.parsers.ethdebug import MultiContractETHDebugParser, ETHDebugDirParser
from soldb.core.evm_repl import EVMDebugger
from soldb.core.serializer import TraceSerializer
from soldb.utils.colors import error, info, warning, number
from soldb.utils.exceptions import format_error_json
from soldb.utils.logging import logger
from soldb.cli.common import (
    get_ethdebug_dirs,
    is_multi_contract_mode,
    load_multi_contract_parser,
    load_abi_files,
    handle_command_error,
    print_connection_info,
)


def simulate_command(args) -> int:
    """
    Execute the simulate command.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    json_mode = getattr(args, 'json', False)
    
    # Normalize addresses
    args = _normalize_addresses(args)
    
    # Validate raw_data vs function_signature
    if not _validate_raw_data_args(args):
        return 1
    
    # Show connection info
    print_connection_info(args.rpc_url, json_mode)
    
    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except Exception as e:
        return _handle_connection_error(e, json_mode)
    
    # Parse and validate value
    token_value = _parse_value(args, tracer, json_mode)
    if token_value is None:
        return 1
    
    # Validate contract address (for non-interactive mode)
    if args.contract_address and not args.interactive:
        if not is_address(args.contract_address):
            print(error(f'Contract not found: {args.contract_address}'))
            print("Please verify:")
            print("  - The address is correct")
            print("  - You're connected to the right network and your contract is deployed")
            return 1
    
    # Load debug info
    source_map = _load_debug_info_for_simulate(tracer, args, json_mode)
    
    # Handle interactive mode
    if args.interactive:
        return _interactive_mode(args, tracer, token_value if args.value else 0)
    
    # Execute simulation
    return _execute_simulation(tracer, args, source_map, token_value, json_mode)


def _normalize_addresses(args):
    """Normalize addresses to checksum format."""
    if args.from_addr:
        args.from_addr = to_checksum_address(args.from_addr)
    if args.contract_address:
        args.contract_address = to_checksum_address(args.contract_address)
    return args


def _validate_raw_data_args(args) -> bool:
    """Validate that raw_data and function_signature are mutually exclusive."""
    if getattr(args, 'raw_data', None):
        if getattr(args, 'function_signature', None) or (hasattr(args, 'function_args') and args.function_args):
            print("Error: When using --raw-data, do not provide function_signature or function_args.")
            return False
    return True


def _handle_connection_error(e: Exception, json_mode: bool) -> int:
    """Handle RPC connection errors."""
    if json_mode:
        json_output = format_error_json(str(e), "ConnectionError")
        print(json.dumps(json_output, indent=2))
    else:
        print(error(str(e)))
    return 1


def _parse_value(args, tracer: TransactionTracer, json_mode: bool) -> Optional[int]:
    """Parse the value argument and return wei amount."""
    if not args.value:
        return 0
    
    try:
        if isinstance(args.value, str) and args.value.endswith('ether'):
            value = args.value.split('ether')[0]
            return tracer.w3.to_wei(float(value), 'ether')
        else:
            return int(args.value)
    except Exception as e:
        error_message = f"Invalid value for --value: {args.value}"
        if json_mode:
            json_output = format_error_json(error_message, "InvalidValue", provided_value=str(args.value))
            print(json.dumps(json_output, indent=2))
        else:
            print(error(error_message))
        return None


def _load_debug_info_for_simulate(tracer: TransactionTracer, args, json_mode: bool) -> dict:
    """Load debug information for simulation."""
    source_map = {}
    ethdebug_dirs = get_ethdebug_dirs(args)
    multi_contract_mode = is_multi_contract_mode(args)
    
    if multi_contract_mode:
        return _load_multi_contract_debug_info(tracer, args, ethdebug_dirs, json_mode)
    elif ethdebug_dirs:
        return _load_single_contract_debug_info(tracer, args, ethdebug_dirs, json_mode)
    else:
        # No debug info - try to load ABI from common locations
        _try_load_abi_from_common_locations(tracer, args.contract_address)
        return source_map


def _load_multi_contract_debug_info(tracer, args, ethdebug_dirs, json_mode) -> dict:
    """Load debug info for multi-contract mode."""
    multi_parser = MultiContractETHDebugParser()
    contracts_file = getattr(args, 'contracts', None)
    
    # Load from contracts mapping file if provided
    if contracts_file:
        try:
            multi_parser.load_from_mapping_file(contracts_file)
        except Exception as e:
            print(f"Error loading contracts mapping file: {e}")
            sys.exit(1)
    
    # Load from ethdebug directories
    if ethdebug_dirs:
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
            for spec in specs:
                _load_contract_from_spec_with_error(multi_parser, spec)
        except ValueError as e:
            sys.stderr.write(f"Error parsing ethdebug directories: {e}\n")
            sys.exit(1)
    
    tracer.multi_contract_parser = multi_parser
    
    # Set primary contract context
    source_map = {}
    primary_contract = multi_parser.get_contract_at_address(args.contract_address)
    if primary_contract:
        tracer.ethdebug_parser = primary_contract.parser
        tracer.srcmap_parser = primary_contract.srcmap_parser
        if primary_contract.parser:
            tracer.ethdebug_parser.debug_dir = str(primary_contract.debug_dir)
        tracer.ethdebug_info = primary_contract.ethdebug_info
        tracer.srcmap_info = primary_contract.srcmap_info
        
        # Get source mapping from active parser
        active_parser = primary_contract.get_parser()
        if active_parser:
            source_map = active_parser.get_source_mapping()
        
        # Load ABI for primary contract
        abi_path = primary_contract.debug_dir / f"{primary_contract.name}.abi"
        if abi_path.exists():
            tracer.load_abi(str(abi_path))
        else:
            for abi_file in Path(primary_contract.debug_dir).glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
    else:
        # No debug info for entrypoint - show warning
        if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
            print(warning(f"Warning: No ETHDebug information for entrypoint contract {args.contract_address}"))
            print(f"Simulation will work but function calls may not be properly decoded.")
            print()
        _try_load_abi_from_common_locations(tracer, args.contract_address)
    
    # Load ABIs for all contracts
    load_abi_files(tracer, multi_parser)
    
    return source_map


def _load_contract_from_spec_with_error(multi_parser, spec):
    """Load contract from spec with error handling."""
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


def _load_single_contract_debug_info(tracer, args, ethdebug_dirs, json_mode) -> dict:
    """Load debug info for single contract mode."""
    try:
        specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
        if not specs:
            print(error("No valid ethdebug directory specified"))
            sys.exit(1)
        spec = specs[0]
        address = to_checksum_address(spec.address) if spec.address else None
        name, ethdebug_dir = spec.name, spec.path
    except ValueError as e:
        print(error(f"Error: {e}"))
        sys.exit(1)
    
    source_map = {}
    
    # Check if address matches
    if args.contract_address and address and args.contract_address.lower() != address.lower():
        # Address doesn't match - show warning
        if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
            print(warning(f"Warning: Contract address {args.contract_address} does not match ETHDebug address {address}"))
            print()
        
        # Still load the ETHDebug info
        if not args.interactive:
            tracer.load_debug_info_auto(ethdebug_dir, name)
            _load_abi_for_contract(tracer, ethdebug_dir)
        _try_load_abi_from_common_locations(tracer, args.contract_address)
    else:
        # Address matches - load debug info
        if not args.interactive:
            try:
                source_map = tracer.load_debug_info_auto(ethdebug_dir, name)
            except FileNotFoundError as e:
                error_msg = str(e)
                # Try to extract compiler version from the error message or debug directory
                from soldb.parsers.ethdebug import ETHDebugParser
                try:
                    compiler_info = ETHDebugParser._get_compiler_info(ethdebug_dir)
                    if compiler_info and compiler_info not in error_msg:
                        error_msg += f" (compiler: {compiler_info})"
                except Exception:
                    pass
                print(error(error_msg))
                sys.exit(1)
            if tracer.ethdebug_info:
                contract_name = tracer.ethdebug_info.contract_name
            elif tracer.srcmap_info:
                contract_name = tracer.srcmap_info.contract_name
            else:
                contract_name = None
            abi_path = ETHDebugDirParser.find_abi_file(spec, contract_name)
            if abi_path:
                tracer.load_abi(abi_path)
    
    # Create multi-contract parser
    multi_parser = MultiContractETHDebugParser()
    if tracer.ethdebug_info or tracer.srcmap_info:
        try:
            multi_parser.load_contract(address, ethdebug_dir, name)
        except FileNotFoundError:
            pass
    load_abi_files(tracer, multi_parser)
    tracer.multi_contract_parser = multi_parser
    
    return source_map


def _load_abi_for_contract(tracer, ethdebug_dir):
    """Load ABI for a contract from its debug directory."""
    contract_name = None
    if tracer.ethdebug_info:
        contract_name = tracer.ethdebug_info.contract_name
    elif tracer.srcmap_info:
        contract_name = tracer.srcmap_info.contract_name
    
    if contract_name:
        abi_path = os.path.join(ethdebug_dir, f"{contract_name}.abi")
        if os.path.exists(abi_path):
            tracer.load_abi(abi_path)
    else:
        for abi_file in Path(ethdebug_dir).glob("*.abi"):
            tracer.load_abi(str(abi_file))
            break


def _try_load_abi_from_common_locations(tracer, contract_address):
    """Try to load ABI from common locations."""
    if contract_address:
        for abi_file in Path(".").glob("*.abi"):
            tracer.load_abi(str(abi_file))
            break


def _execute_simulation(tracer, args, source_map, token_value, json_mode) -> int:
    """Execute the simulation and output results."""
    # Handle raw data vs function signature
    if getattr(args, 'raw_data', None):
        return _simulate_with_raw_data(tracer, args, source_map, token_value, json_mode)
    else:
        return _simulate_with_function(tracer, args, source_map, token_value, json_mode)


def _simulate_with_raw_data(tracer, args, source_map, token_value, json_mode) -> int:
    """Execute simulation with raw calldata."""
    calldata = args.raw_data
    
    try:
        trace = tracer.simulate_call_trace(
            args.contract_address, args.from_addr, calldata, 
            args.block, args.tx_index, token_value
        )
    except Exception as e:
        if json_mode:
            json_output = format_error_json(f"Error during simulation: {str(e)}", "SimulationError")
            print(json.dumps(json_output, indent=2))
        else:
            print(f"Error during simulation: {e}")
        return 1
    
    return _output_trace(tracer, trace, args, source_map, json_mode)


def _simulate_with_function(tracer, args, source_map, token_value, json_mode) -> int:
    """Execute simulation with function signature and arguments."""
    if not getattr(args, 'function_signature', None):
        print('Error: function_signature is required if --raw-data is not provided')
        return 1
    
    # Parse function signature
    func_name, func_types = _parse_signature(args.function_signature)
    
    # Find ABI item
    abi_item = _find_abi_item(tracer, func_name, func_types)
    has_abi = len(tracer.function_abis) > 0
    
    # Handle ABI warnings
    if has_abi and not abi_item:
        print(f'Function {args.function_signature} not found in ABI')
        available_functions = [item["name"] for item in tracer.function_abis.values()]
        if available_functions:
            print(f'Available functions: {available_functions}')
        print('Proceeding with function signature parsing...')
    elif not has_abi:
        print(f'No ABI files found. Proceeding with function signature: {args.function_signature}')
    
    # Parse arguments
    parsed_args = _parse_function_args(args, func_types, abi_item, has_abi)
    if parsed_args is None:
        return 1
    
    # Encode calldata
    calldata = _encode_calldata(func_name, func_types, parsed_args)
    if calldata is None:
        return 1
    
    # Execute simulation
    try:
        trace = tracer.simulate_call_trace(
            args.contract_address, args.from_addr, calldata,
            args.block, args.tx_index, token_value
        )
    except Exception as e:
        if json_mode:
            json_output = format_error_json(f"Error during simulation: {str(e)}", "SimulationError")
            print(json.dumps(json_output, indent=2))
        else:
            print(f"Error during simulation: {e}")
        return 1
    
    return _output_trace(tracer, trace, args, source_map, json_mode)


def _parse_signature(signature: str) -> Tuple[str, List[str]]:
    """Parse function signature into name and types."""
    from soldb.parsers.abi import parse_signature
    return parse_signature(signature)


def _find_abi_item(tracer, func_name: str, func_types: List[str]) -> Optional[dict]:
    """Find matching ABI item for function."""
    from soldb.parsers.abi import match_abi_types
    
    # First try exact name match
    for item in tracer.function_abis.values():
        if item['name'] == func_name:
            abi_input_types = [inp['type'] for inp in item['inputs']]
            if match_abi_types(func_types, abi_input_types):
                return item
    
    # Try more flexible matching
    for item in tracer.function_abis.values():
        if item['name'] == func_name:
            abi_input_types = [inp['type'] for inp in item['inputs']]
            if len(func_types) == len(abi_input_types):
                converted_types = []
                for parsed_type in func_types:
                    if parsed_type.startswith('(') and parsed_type.endswith(')'):
                        converted_types.append('tuple')
                    else:
                        converted_types.append(parsed_type)
                if converted_types == abi_input_types:
                    return item
    
    return None


def _parse_function_args(args, func_types: List[str], abi_item: Optional[dict], has_abi: bool) -> Optional[List[Any]]:
    """Parse function arguments based on types."""
    from soldb.parsers.abi import parse_tuple_arg
    
    if has_abi and abi_item:
        input_types = [inp['type'] for inp in abi_item['inputs']]
        if len(args.function_args) != len(input_types):
            print(f'Function {args.function_signature} expects {len(input_types)} arguments, got {len(args.function_args)}')
            return None
        
        parsed_args = []
        for val, typ, abi_input in zip(args.function_args, input_types, abi_item['inputs']):
            parsed_arg = _parse_single_arg(val, typ, abi_input)
            if parsed_arg is None:
                return None
            parsed_args.append(parsed_arg)
    else:
        if len(args.function_args) != len(func_types):
            print(f'Function {args.function_signature} expects {len(func_types)} arguments, got {len(args.function_args)}')
            return None
        
        parsed_args = []
        for val, typ in zip(args.function_args, func_types):
            parsed_arg = _parse_single_arg_simple(val, typ)
            parsed_args.append(parsed_arg)
    
    return parsed_args


def _parse_single_arg(val: str, typ: str, abi_input: dict) -> Any:
    """Parse a single argument with ABI type information."""
    from soldb.parsers.abi import parse_tuple_arg
    
    if typ.startswith('uint') or typ.startswith('int'):
        return int(val, 0)
    elif typ == 'address':
        return val
    elif typ.startswith('bytes'):
        if val.startswith('0x'):
            return bytes.fromhex(val[2:])
        return bytes.fromhex(val)
    elif typ.startswith('tuple'):
        try:
            parsed_val = ast.literal_eval(val)
            if 'components' in abi_input:
                return parse_tuple_arg(parsed_val, abi_input)
            return parsed_val
        except Exception as e:
            print(f"Error parsing tuple argument: {val} ({e})")
            return None
    else:
        return val


def _parse_single_arg_simple(val: str, typ: str) -> Any:
    """Parse a single argument based on type (no ABI)."""
    if typ.startswith('uint') or typ.startswith('int'):
        return int(val, 0)
    elif typ == 'address':
        return val
    elif typ.startswith('bytes'):
        if val.startswith('0x'):
            return bytes.fromhex(val[2:])
        return bytes.fromhex(val)
    elif typ == 'string':
        return val
    elif typ == 'bool':
        return val.lower() in ('true', '1', 'yes')
    else:
        return val


def _encode_calldata(func_name: str, func_types: List[str], parsed_args: List[Any]) -> Optional[str]:
    """Encode function call as calldata."""
    try:
        encoded_args = encode(func_types, parsed_args)
    except Exception as e:
        print(f'Error encoding arguments: {e}')
        return None
    
    function_signature = f"{func_name}({','.join(func_types)})"
    selector = keccak(function_signature.encode())[:4]
    
    return "0x" + selector.hex() + encoded_args.hex()


def _output_trace(tracer, trace, args, source_map, json_mode) -> int:
    """Output the trace in the requested format."""
    function_calls = tracer.analyze_function_calls(trace)
    
    if json_mode:
        serializer = TraceSerializer()
        tracer.to_addr = args.contract_address
        json_output = serializer.serialize_trace(
            trace,
            function_calls,
            getattr(tracer, 'ethdebug_info', None),
            getattr(tracer, 'multi_contract_parser', None),
            tracer
        )
        print(json.dumps(json_output, indent=2))
    elif getattr(args, 'raw', False):
        max_steps = getattr(args, 'max_steps', None)
        tracer.print_trace(trace, source_map, max_steps)
    else:
        tracer.print_function_trace(trace, function_calls)
    
    return 0


def _interactive_mode(args, tracer, value: int = 0) -> int:
    """Start interactive debugger mode."""
    from soldb.core.auto_deploy import AutoDeployDebugger
    
    # Validate required arguments
    if not getattr(args, 'contract_address', None):
        print('Error: contract address is required')
        return 1
    
    contract_arg = args.contract_address
    session = None
    contract_address = None
    ethdebug_dir = None
    abi_path = None
    contract_name = None
    
    # Check if it's a file path or address
    is_contract_file = os.path.exists(contract_arg) and contract_arg.endswith('.sol')
    is_contract_address = contract_arg.startswith('0x') and is_address(contract_arg)
    
    if not is_contract_file and not is_contract_address:
        print(error(f'Contract not found: {contract_arg}'))
        print("Please verify:")
        print("  - The address is correct")
        print("  - You're connected to the right network and your contract is deployed")
        return 1
    
    if not getattr(args, 'function_signature', None):
        print('Error: function signature is required')
        return 1
    
    if is_contract_file:
        session, contract_address, ethdebug_dir, abi_path = _setup_auto_deploy(args)
        if session is None:
            return 1
    elif is_contract_address:
        if not args.ethdebug_dir and not getattr(args, 'contracts', None):
            print(error("Error: --ethdebug-dir is required when using --contract-address."))
            return 1
        
        contract_address = args.contract_address
        ethdebug_dir, contract_name = _get_ethdebug_dir_for_interactive(tracer, args)
    
    print("\nStarting debugger...")
    debugger = EVMDebugger(
        contract_address=str(contract_address),
        rpc_url=(session.rpc_url if session else args.rpc_url),
        ethdebug_dir=ethdebug_dir,
        function_name=getattr(args, 'function_signature', None),
        function_args=getattr(args, 'function_args', []),
        abi_path=abi_path,
        from_addr=args.from_addr,
        block=args.block,
        tracer=tracer,
        contract_name=contract_name,
        value=value
    )
    
    # Baseline snapshot
    if not getattr(args, 'no_snapshot', False):
        debugger.tracer.snapshot_state()
    
    debugger._do_interactive()
    
    try:
        debugger.cmdloop()
        if getattr(args, 'fork_url', None) and session and not getattr(args, 'keep_fork', False):
            session.cleanup()
    except KeyboardInterrupt:
        print("\nInterrupted")
        if getattr(args, 'fork_url', None) and session and not getattr(args, 'keep_fork', False):
            print("Stopping anvil fork...")
            session.cleanup()
        return 1
    
    return 0


def _setup_auto_deploy(args):
    """Set up auto-deploy debugger session."""
    from soldb.core.auto_deploy import AutoDeployDebugger
    
    try:
        session = AutoDeployDebugger(
            contract_file=args.contract_address,
            rpc_url=args.rpc_url,
            constructor_args=getattr(args, 'constructor_args', []),
            solc_path=args.solc_path,
            dual_compile=args.dual_compile,
            keep_build=args.keep_build,
            output_dir=args.output_dir,
            production_dir=args.production_dir,
            json_output=getattr(args, 'json', False),
            save_config=args.save_config,
            verify_version=args.verify_version,
            use_cache=not args.no_cache,
            cache_dir=args.cache_dir,
            fork_url=args.fork_url,
            fork_block=args.fork_block,
            auto_snapshot=not args.no_snapshot,
            keep_fork=args.keep_fork,
            reuse_fork=args.reuse_fork,
            fork_port=args.fork_port,
        )
        return session, session.contract_address, str(session.debug_dir), str(session.abi_path)
    except Exception as e:
        print(error(f"Debug session failed: {e}"))
        return None, None, None, None


def _get_ethdebug_dir_for_interactive(tracer, args):
    """Get ETHDebug directory for interactive mode."""
    contract_name = None
    ethdebug_dir = None
    
    if getattr(tracer, 'multi_contract_parser', None):
        entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(args.contract_address)
        if entrypoint_contract:
            return str(entrypoint_contract.debug_dir), entrypoint_contract.name
    
    # Fallback to parsing ethdebug_dir
    ethdebug_spec = args.ethdebug_dir[0] if isinstance(args.ethdebug_dir, list) else args.ethdebug_dir
    try:
        specs = ETHDebugDirParser.parse_ethdebug_dirs([ethdebug_spec])
        if specs:
            return specs[0].path, specs[0].name
    except ValueError:
        if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
            parts = ethdebug_spec.split(':', 2)
            if len(parts) >= 3:
                return parts[2], parts[1]
            elif len(parts) == 2:
                return parts[1], None
    
    return ethdebug_spec, None
