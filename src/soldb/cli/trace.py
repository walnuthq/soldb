"""
Trace command implementation.

This module handles tracing existing blockchain transactions,
providing step-by-step EVM execution details with source mapping.
"""

import sys
import os
import json
from pathlib import Path
from typing import Optional, Any

from soldb.transaction_tracer import TransactionTracer
from soldb.multi_contract_ethdebug_parser import MultiContractETHDebugParser
from soldb.ethdebug_dir_parser import ETHDebugDirParser
from soldb.evm_repl import EVMDebugger
from soldb.json_serializer import TraceSerializer
from soldb.colors import error, info, warning
from soldb.utils.exceptions import format_error_json
from soldb.utils.logging import logger
from soldb.cli.common import (
    create_tracer,
    get_ethdebug_dirs,
    is_multi_contract_mode,
    load_multi_contract_parser,
    load_abi_files,
    handle_command_error,
    print_connection_info,
)


def trace_command(args) -> int:
    """
    Execute the trace command.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    json_mode = getattr(args, 'json', False)
    
    # Show connection info
    print_connection_info(args.rpc, json_mode)
    
    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc, quiet_mode=json_mode)
    except Exception as e:
        return _handle_connection_error(e, json_mode)
    
    # Trace the transaction
    trace = _trace_transaction(tracer, args.tx_hash, json_mode)
    if trace is None:
        return 1
    
    # Check if debug trace is available
    if not trace.debug_trace_available:
        return _handle_debug_trace_unavailable(trace, json_mode)
    
    # Load debug info and source mapping
    source_map, debug_file = _load_debug_info(tracer, trace, args, json_mode)
    if source_map is None:
        return 1
    
    # Print trace or start interactive debugger
    if args.interactive:
        return _start_interactive_mode(tracer, trace, args, debug_file)
    else:
        return _print_trace_output(tracer, trace, source_map, args, json_mode)


def _handle_connection_error(e: Exception, json_mode: bool) -> int:
    """Handle RPC connection errors."""
    if json_mode:
        json_output = format_error_json(str(e), "ConnectionError")
        print(json.dumps(json_output, indent=2))
    else:
        print(error(str(e)))
    return 1


def _trace_transaction(tracer: TransactionTracer, tx_hash: str, json_mode: bool):
    """Trace a transaction and return the trace object."""
    if not json_mode:
        print(f"Loading transaction {info(tx_hash)}...")
        sys.stdout.flush()
    
    try:
        return tracer.trace_transaction(tx_hash)
    except ValueError as e:
        if json_mode:
            json_output = format_error_json(str(e), "TransactionError")
            print(json.dumps(json_output, indent=2))
        else:
            print(error(str(e)))
        return None


def _handle_debug_trace_unavailable(trace, json_mode: bool) -> int:
    """Handle case when debug trace is not available."""
    if json_mode:
        base_message = "debug_traceTransaction unavailable"
        error_detail = _extract_error_detail(trace.error) if trace.error else None
        error_message = f"{base_message}: {error_detail}" if error_detail else base_message
        
        json_output = format_error_json(
            error_message,
            "DebugTraceUnavailable",
            tx_hash=trace.tx_hash,
            from_address=trace.from_addr,
            to_address=trace.to_addr,
            gas_used=trace.gas_used,
            status="SUCCESS" if trace.success else "REVERTED",
            trace_error=trace.error
        )
        print(json.dumps(json_output, indent=2))
    else:
        print(f"\n{error('Error: debug_traceTransaction not available')}")
        print(f"The RPC endpoint returned: {trace.error or 'execution timeout'}")
        print(f"\nTransaction details:")
        print(f"  Hash: {trace.tx_hash}")
        print(f"  From: {trace.from_addr}")
        print(f"  To: {trace.to_addr}")
        print(f"  Gas used: {trace.gas_used}")
        print(f"  Status: {'SUCCESS' if trace.success else 'REVERTED'}")
    return 1


def _extract_error_detail(trace_error: str) -> Optional[str]:
    """Extract meaningful error detail from trace error string."""
    if not isinstance(trace_error, str):
        return str(trace_error) if trace_error else None
    
    try:
        import ast
        if trace_error.strip().startswith('{'):
            error_dict = ast.literal_eval(trace_error)
            if isinstance(error_dict, dict) and 'message' in error_dict:
                return error_dict['message']
    except:
        pass
    
    return trace_error


def _load_debug_info(tracer, trace, args, json_mode: bool):
    """Load debug information and return source map."""
    source_map = {}
    debug_file = getattr(args, 'debug_info_from_zasm_file', None)
    
    # Try to find debug file if not provided
    if not debug_file:
        debug_file = _find_debug_file_for_trace(trace, args.tx_hash)
    
    # Check for multi-contract mode
    if is_multi_contract_mode(args):
        source_map = _load_multi_contract_debug_info(tracer, trace, args, json_mode)
        if source_map is None:
            return None, debug_file
    elif args.ethdebug_dir and len(args.ethdebug_dir) == 1:
        source_map = _load_single_contract_debug_info(tracer, trace, args, json_mode)
        if source_map is None:
            return None, debug_file
    elif debug_file:
        source_map = tracer.load_debug_info(debug_file)
        debug_dir = os.path.dirname(debug_file)
        for abi_file in Path(debug_dir).glob("*.abi"):
            tracer.load_abi(str(abi_file))
            break
    
    return source_map, debug_file


def _find_debug_file_for_trace(trace, tx_hash: str) -> Optional[str]:
    """Try to find debug file for a transaction."""
    from soldb.cli.common import find_debug_file
    
    # For deployment transactions
    if not trace.to_addr:
        debug_dir = Path("debug")
        if not debug_dir.exists():
            debug_dir = Path(".")
        deployment_file = debug_dir / "deployment.json"
        if deployment_file.exists():
            try:
                with open(deployment_file) as f:
                    deployment = json.load(f)
                    if deployment.get('transaction', '').lower() == tx_hash.lower():
                        # Legacy .zasm support - deprecated
                        for zasm_file in debug_dir.glob("*.zasm"):
                            logger.warning("Using legacy .zasm debug file format. Consider migrating to ETHDebug.")
                            return str(zasm_file)
            except Exception:
                pass
    else:
        # Try to find debug file for contract
        return find_debug_file(trace.to_addr)
    
    return None


def _find_debug_file(contract_addr: str) -> Optional[str]:
    """Try to find debug file for a contract."""
    from soldb.cli.common import find_debug_file
    return find_debug_file(contract_addr)


def _load_multi_contract_debug_info(tracer, trace, args, json_mode: bool):
    """Load debug info for multi-contract mode."""
    ethdebug_dirs = get_ethdebug_dirs(args)
    contracts_file = getattr(args, 'contracts', None)
    
    multi_parser, errors = load_multi_contract_parser(ethdebug_dirs, contracts_file, json_mode)
    
    if errors:
        for err in errors:
            print(error(err))
        return None
    
    # Set the multi-contract parser on the tracer
    tracer.multi_contract_parser = multi_parser
    
    # Set primary contract based on transaction
    source_map = {}
    if trace.to_addr:
        primary_contract = multi_parser.get_contract_at_address(trace.to_addr)
        if primary_contract:
            tracer.ethdebug_parser = primary_contract.parser
            tracer.srcmap_parser = primary_contract.srcmap_parser
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
    
    # Load ABIs for all contracts
    load_abi_files(tracer, multi_parser)
    
    return source_map


def _load_single_contract_debug_info(tracer, trace, args, json_mode: bool):
    """Load debug info for single contract mode."""
    try:
        specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
        if not specs:
            print(error("No valid ethdebug directory specified"))
            return None
        spec = specs[0]
        address, name, ethdebug_dir = spec.address, spec.name, spec.path
    except ValueError as e:
        print(error(f"Error: {e}"))
        return None
    
    source_map = {}
    
    # Load ETHDebug info for non-interactive mode only
    if not args.interactive:
        try:
            source_map = tracer.load_ethdebug_info_auto(ethdebug_dir, name)
        except FileNotFoundError as e:
            error_msg = str(e)
            # Try to extract compiler version from the error message or debug directory
            from soldb.ethdebug_parser import ETHDebugParser
            try:
                compiler_info = ETHDebugParser._get_compiler_info(ethdebug_dir)
                if compiler_info and compiler_info not in error_msg:
                    error_msg += f" (compiler: {compiler_info})"
            except Exception:
                pass
            print(error(error_msg))
            return None
        
        # Try to load ABI
        if tracer.ethdebug_info:
            contract_name = tracer.ethdebug_info.contract_name
        elif tracer.srcmap_info:
            contract_name = tracer.srcmap_info.contract_name
        else:
            contract_name = None
        abi_path = ETHDebugDirParser.find_abi_file(spec, contract_name)
        if abi_path:
            tracer.load_abi(abi_path)
    
    # Create multi-contract parser for additional contracts
    multi_parser = MultiContractETHDebugParser()
    if tracer.ethdebug_info or tracer.srcmap_info:
        try:
            multi_parser.load_contract(address, ethdebug_dir, name)
        except FileNotFoundError:
            pass  # Already loaded above
    
    # Load ABIs
    load_abi_files(tracer, multi_parser)
    
    # Set the multi-contract parser
    tracer.multi_contract_parser = multi_parser
    
    return source_map


def _print_trace_output(tracer, trace, source_map, args, json_mode: bool) -> int:
    """Print trace output based on requested format."""
    if json_mode:
        function_calls = tracer.analyze_function_calls(trace)
        serializer = TraceSerializer()
        tracer.to_addr = trace.to_addr
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
        function_calls = tracer.analyze_function_calls(trace)
        tracer.print_function_trace(trace, function_calls)
    
    return 0


def _start_interactive_mode(tracer, trace, args, debug_file) -> int:
    """Start the interactive debugger."""
    print("\nStarting interactive debugger...")
    
    # Determine the correct ethdebug_dir for the entrypoint contract
    entrypoint_ethdebug_dir = _get_entrypoint_ethdebug_dir(tracer, trace, args)
    
    # Extract contract name
    contract_name = _get_entrypoint_contract_name(tracer, trace, args)
    
    debugger = EVMDebugger(
        contract_address=trace.to_addr,
        debug_file=debug_file,
        rpc_url=args.rpc,
        ethdebug_dir=entrypoint_ethdebug_dir,
        tracer=tracer,
        contract_name=contract_name,
        abi_path=None
    )
    
    # Pre-load the trace and function analysis
    function_calls = tracer.analyze_function_calls(trace)
    debugger.current_trace = trace
    debugger.current_step = 0
    debugger.function_trace = function_calls
    
    # Start at first function after dispatcher
    if len(function_calls) > 1:
        debugger.current_step = function_calls[1].entry_step
        debugger.current_function = function_calls[1]
    
    debugger.do_run(trace.tx_hash)
    
    # Start REPL
    try:
        debugger.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted")
    
    return 0


def _get_entrypoint_ethdebug_dir(tracer, trace, args) -> Optional[str]:
    """Get the ETHDebug directory for the entrypoint contract."""
    if tracer.multi_contract_parser and trace.to_addr:
        entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(trace.to_addr)
        if entrypoint_contract:
            return str(entrypoint_contract.debug_dir)
    
    if args.ethdebug_dir:
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
            if specs:
                return specs[0].path
            return args.ethdebug_dir[0]
        except ValueError:
            ethdebug_spec = args.ethdebug_dir[0]
            if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                parts = ethdebug_spec.split(':', 2)
                if len(parts) >= 3:
                    return parts[2]
                elif len(parts) == 2:
                    return parts[1]
            return ethdebug_spec
    
    return None


def _get_entrypoint_contract_name(tracer, trace, args) -> Optional[str]:
    """Get the contract name for the entrypoint contract."""
    if tracer.multi_contract_parser and trace.to_addr:
        entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(trace.to_addr)
        if entrypoint_contract:
            return entrypoint_contract.name
    
    if args.ethdebug_dir:
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
            if specs:
                return specs[0].name
        except ValueError:
            ethdebug_spec = args.ethdebug_dir[0]
            if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                parts = ethdebug_spec.split(':', 2)
                if len(parts) >= 3:
                    return parts[1]
    
    return None
