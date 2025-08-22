#!/usr/bin/env python3
"""
Main entry point for soldb
"""

import sys
import os
import argparse
import json
from pathlib import Path
import ast

from .transaction_tracer import TransactionTracer, SourceMapper
from .evm_repl import EVMDebugger
from .abi_utils import match_abi_types, match_single_type, parse_signature, parse_tuple_arg
from .multi_contract_ethdebug_parser import MultiContractETHDebugParser
from .json_serializer import TraceSerializer
from .colors import error
from .auto_deploy import AutoDeployDebugger


def find_debug_file(contract_addr: str) -> str:
    """Try to find debug file for a contract."""
    debug_dir = Path("debug")
    if debug_dir.exists():
        # Look for deployment.json
        deployment_file = debug_dir / "deployment.json"
        if deployment_file.exists():
            with open(deployment_file) as f:
                deployment = json.load(f)
                if deployment.get('address', '').lower() == contract_addr.lower():
                    # Find matching .zasm file
                    for zasm_file in debug_dir.glob("*.runtime.zasm"):
                        return str(zasm_file)
    
    # Look for any .zasm file
    for zasm_file in Path(".").glob("**/*.runtime.zasm"):
        return str(zasm_file)
    
    return None


def trace_command(args):
    """Execute the trace command."""
    
    # Create tracer
    tracer = TransactionTracer(args.rpc, quiet_mode=args.json)
    
    # Trace transaction
    if not args.json:
        print(f"Loading transaction {args.tx_hash}...")
        sys.stdout.flush()  # Ensure output order
    trace = tracer.trace_transaction(args.tx_hash)
    
    # Check if debug trace is available
    if not trace.debug_trace_available:
        if args.json:
            # Output minimal JSON with error
            json_output = {
                "soldbFailed": "debug_traceTransaction unavailable",
                "tx_hash": trace.tx_hash,
                "from": trace.from_addr,
                "to": trace.to_addr,
                "gas_used": trace.gas_used,
                "status": "SUCCESS" if trace.success else "REVERTED",
                "error": trace.error
            }
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
    
    # Try to find debug file if not provided
    debug_file = getattr(args, 'debug_info_from_zasm_file', None)
    if not debug_file:
        # For deployment transactions, check deployment.json
        if not trace.to_addr:  # Deployment transaction
            debug_dir = Path("debug")
            if not debug_dir.exists():
                debug_dir = Path(".")
            deployment_file = debug_dir / "deployment.json"
            if deployment_file.exists():
                with open(deployment_file) as f:
                    deployment = json.load(f)
                    if deployment.get('transaction', '').lower() == args.tx_hash.lower():
                        # Find matching .zasm file
                        for zasm_file in debug_dir.glob("*.zasm"):
                            debug_file = str(zasm_file)
                            print(f"Found debug file for deployment: {debug_file}")
                            break
                        
        else:
            debug_file = find_debug_file(trace.to_addr)
            if debug_file:
                print(f"Found debug file: {debug_file}")
    
    # Load debug info (but skip the output if going into interactive mode)
    source_map = {}
    
    # Check if multi-contract mode is enabled or multiple directories provided
    if args.multi_contract or (args.ethdebug_dir and len(args.ethdebug_dir) > 1) or args.contracts:
        # Multi-contract mode
        multi_parser = MultiContractETHDebugParser()
        
        # Load from contracts mapping file if provided
        if args.contracts:
            multi_parser.load_from_mapping_file(args.contracts)
        
        # Load from ethdebug directories
        if args.ethdebug_dir:
            for ethdebug_spec in args.ethdebug_dir:
                # Parse address:path format
                address = None
                name = None
                path = ethdebug_spec
                parts = ethdebug_spec.split(':', 2)
                if len(parts) == 3:
                    address, name, path = parts
                elif len(parts) == 2:
                    address, path = parts
                try:
                    if address and name:
                        multi_parser.load_contract(address, path, name)
                    elif address:
                        multi_parser.load_contract(address, path)
                    else:
                        # Try to load from deployment.json in the directory
                        # NOTE: This does not make sense because the contract that we want to debug is probably already deployed
                        # and we do not have deployment.json for it.
                        deployment_file = Path(ethdebug_spec) / "deployment.json"
                        if deployment_file.exists():
                            multi_parser.load_from_deployment(deployment_file)
                        else:
                            print(f"Warning: No deployment.json found in {ethdebug_spec}, skipping...\n")
                except Exception as e:
                    print(f"Error loading contract {address or ''} from {path}: {e}\n")
                    sys.exit(1)
        # Set the multi-contract parser on the tracer
        tracer.multi_contract_parser = multi_parser
        
        # Try to set primary contract based on transaction
        if trace.to_addr:
            primary_contract = multi_parser.get_contract_at_address(trace.to_addr)
            if primary_contract:
                tracer.ethdebug_parser = primary_contract.parser
                tracer.ethdebug_info = primary_contract.ethdebug_info
                source_map = primary_contract.parser.get_source_mapping()
                
                # Load ABI for primary contract
                abi_path = primary_contract.debug_dir / f"{primary_contract.name}.abi"
                if abi_path.exists():
                    tracer.load_abi(str(abi_path))
                
                # Load ABIs for all contracts in multi-contract mode
                for addr, contract_info in multi_parser.contracts.items():
                    abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                    if abi_path.exists():
                        tracer.load_abi(str(abi_path))
    
    elif args.ethdebug_dir and len(args.ethdebug_dir) == 1:
        # Single contract mode (backward compatibility)
        ethdebug_dir = args.ethdebug_dir[0]
        if args.interactive:
            # Suppress output for interactive mode
            import io
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                source_map = tracer.load_ethdebug_info(ethdebug_dir)
        else:
            source_map = tracer.load_ethdebug_info(ethdebug_dir)
        # Try to load ABI from ethdebug directory
        if tracer.ethdebug_info:
            abi_path = os.path.join(ethdebug_dir, f"{tracer.ethdebug_info.contract_name}.abi")
            if os.path.exists(abi_path):
                tracer.load_abi(abi_path)
        else:
            # Try to find any ABI file in the directory
            for abi_file in Path(ethdebug_dir).glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
    elif debug_file:
        # Load debug info from zasm format
        source_map = tracer.load_debug_info(debug_file)
        # Try to find ABI in same directory
        debug_dir = os.path.dirname(debug_file)
        for abi_file in Path(debug_dir).glob("*.abi"):
            tracer.load_abi(str(abi_file))
            break
    
    # Print trace based on mode (but skip if going into interactive mode)
    if not args.interactive:
        if args.json:
            # Output JSON format for web app
            function_calls = tracer.analyze_function_calls(trace)
            serializer = TraceSerializer()
            # Update tracer to have the trace's to_addr for ABI mapping
            tracer.to_addr = trace.to_addr
            json_output = serializer.serialize_trace(
                trace, 
                function_calls,
                getattr(tracer, 'ethdebug_info', None),
                getattr(tracer, 'multi_contract_parser', None),
                tracer
            )
            print(json.dumps(json_output, indent=2))
        elif args.raw:
            # Show detailed instruction trace
            tracer.print_trace(trace, source_map, args.max_steps)
        else:
            # Show pretty function call trace
            function_calls = tracer.analyze_function_calls(trace)
            tracer.print_function_trace(trace, function_calls)
    else:
        # Just analyze function calls for interactive mode
        function_calls = tracer.analyze_function_calls(trace)
    
    # Start interactive debugger if requested
    if args.interactive:
        print("\nStarting interactive debugger...")
        
        debugger = EVMDebugger(
            contract_address=trace.to_addr,
            debug_file=debug_file,
            rpc_url=args.rpc,
            ethdebug_dir=args.ethdebug_dir[0] if args.ethdebug_dir else None,
            multi_contract_parser=getattr(tracer, 'multi_contract_parser', None)
        )
        
        # Pre-load the trace and function analysis
        debugger.current_trace = trace
        debugger.current_step = 0
        debugger.function_trace = function_calls
        
        # Set dynamic intro message based on pre-loaded trace
        debugger._set_intro_message()
        
        # Start at first meaningful function, but be conservative
        if len(function_calls) > 1:
            # Check if the first function after dispatcher is reasonable
            first_func = function_calls[1]
            if first_func.entry_step < len(trace.steps) - 10:  # Leave some room at the end
                debugger.current_step = first_func.entry_step
                debugger.current_function = first_func
            # Otherwise, stay at step 0
        
        # Start REPL
        try:
            debugger.cmdloop()
        except KeyboardInterrupt:
            print("\nInterrupted")
    
    return 0

def simulate_command(args):
    """Execute the simulate command."""

    # If --raw-data is provided, do not provide function_signature or function_args
    if getattr(args, 'raw_data', None):
        if getattr(args, 'function_signature', None) or (hasattr(args, 'function_args') and args.function_args):
            print("Error: When using --raw-data, do not provide function_signature or function_args.")
            sys.exit(1)

    # Create tracer
    tracer = TransactionTracer(args.rpc_url)
    source_map = {}

    # Multi-contract mode detection (same as trace_command)
    multi_contract_mode = False
    ethdebug_dirs = []
    if hasattr(args, 'ethdebug_dir') and args.ethdebug_dir:
        if isinstance(args.ethdebug_dir, list):
            ethdebug_dirs = args.ethdebug_dir
        else:
            ethdebug_dirs = [args.ethdebug_dir]
    if getattr(args, 'multi_contract', False) or (ethdebug_dirs and len(ethdebug_dirs) > 1) or getattr(args, 'contracts', None):
        multi_contract_mode = True

    if multi_contract_mode:
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
            for ethdebug_spec in ethdebug_dirs:
                # New format: address[:name]:path or address:path or just path
                address = None
                name = None
                path = ethdebug_spec
                parts = ethdebug_spec.split(':', 2)
                if len(parts) == 3:
                    address, name, path = parts
                elif len(parts) == 2:
                    address, path = parts
                # Call load_contract with address, path, name
                try:
                    if address and name:
                        multi_parser.load_contract(address, path, name)
                    elif address:
                        multi_parser.load_contract(address, path)
                    else:
                        deployment_file = Path(path) / "deployment.json"
                        if deployment_file.exists():
                            try:
                                multi_parser.load_from_deployment(deployment_file)
                            except Exception as e:
                                sys.stderr.write(f"Error loading deployment.json from {path}: {e}\n")
                                sys.exit(1)
                        else:
                            sys.stderr.write(f"Warning: No deployment.json found in {path}, skipping...\n")
                except Exception as e:
                    sys.stderr.write(f"Error loading contract {address or ''} from {path}: {e}\n")
                    sys.exit(1)
        tracer.multi_contract_parser = multi_parser

        # Set primary contract context for simulation
        primary_contract = multi_parser.get_contract_at_address(args.contract_address)
        if not primary_contract:
            print(f"Error: Contract address {args.contract_address} not found in loaded debug info.")
            print(f"Loaded contracts: {[addr for addr in multi_parser.contracts.keys()]}")
            sys.exit(1)
        tracer.ethdebug_parser = primary_contract.parser
        tracer.ethdebug_info = primary_contract.ethdebug_info
        source_map = primary_contract.parser.get_source_mapping()
        # Load ABI for primary contract
        abi_path = primary_contract.debug_dir / f"{primary_contract.name}.abi"
        if abi_path.exists():
            tracer.load_abi(str(abi_path))
        else:
            # Try to find any ABI file in the directory
            for abi_file in Path(primary_contract.debug_dir).glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
        # Load ABIs for ALL contracts that might be called during simulation
        for addr, contract_info in multi_parser.contracts.items():
            abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
            if abi_path.exists():
                tracer.load_abi(str(abi_path))
                
    elif ethdebug_dirs:
        # Single contract mode (backward compatibility)
        ethdebug_dir = ethdebug_dirs[0]
        source_map = tracer.load_ethdebug_info(ethdebug_dir)
        if tracer.ethdebug_info:
            abi_path = os.path.join(ethdebug_dir, f"{tracer.ethdebug_info.contract_name}.abi")
            if os.path.exists(abi_path):
                tracer.load_abi(abi_path)
        else:
            for abi_file in Path(ethdebug_dir).glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
    else:
        # No debug info provided - simulate without source code
        # Try to load ABI from common locations if available
        if args.contract_address:
            # Try to find ABI in current directory
            for abi_file in Path(".").glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
    # If raw_data is provided, use it directly as calldata
    if getattr(args, 'raw_data', None):
        calldata = args.raw_data
        
        # Prepare call_obj
        call_obj = {
            'to': args.contract_address,
            'from': args.from_addr,
            'data': calldata,
            'value': args.value
        }
        block = args.block
        try:
            trace = tracer.simulate_call_trace(
                args.contract_address, args.from_addr, calldata, block, args.tx_index, args.value
            )
        except Exception as e:
            print(f"Error during simulation: {e}")
            sys.exit(1)
        function_calls = tracer.analyze_function_calls(trace)
        if getattr(args, 'json', False):
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
        else:
            tracer.print_function_trace(trace, function_calls)
        return 0

    # Otherwise, use function_signature and function_args
    if not getattr(args, 'function_signature', None):
        print('Error: function_signature is required if --raw-data is not provided')
        sys.exit(1)
    func_name, func_types = parse_signature(args.function_signature)
    abi_item = None
    # First try exact name match
    for item in tracer.function_abis.values():
        if item['name'] == func_name:
            abi_input_types = [inp['type'] for inp in item['inputs']]
            if match_abi_types(func_types, abi_input_types):
                abi_item = item
                break
    # If not found, try more flexible matching
    if not abi_item:
        for item in tracer.function_abis.values():
            if item['name'] == func_name:
                abi_input_types = [inp['type'] for inp in item['inputs']]
                
                # For tuple types, we need to handle the conversion
                if len(func_types) == len(abi_input_types):
                    # Convert tuple types to match ABI format
                    converted_types = []
                    for parsed_type in func_types:
                        if parsed_type.startswith('(') and parsed_type.endswith(')'):
                            converted_types.append('tuple')
                        else:
                            converted_types.append(parsed_type)
                    if converted_types == abi_input_types:
                        abi_item = item
                        break
    if not abi_item:
        print(f'Function {args.function_signature} not found in ABI')
        print(f'Available functions: {[item["name"] for item in tracer.function_abis.values()]}')
        sys.exit(1)
    input_types = [inp['type'] for inp in abi_item['inputs']]
    
    # Parse function_args from CLI to correct types
    if len(args.function_args) != len(input_types):
        print(f'Function {args.function_signature} expects {len(input_types)} arguments, got {len(args.function_args)}')
        sys.exit(1)
    parsed_args = []
    for val, typ, abi_input in zip(args.function_args, input_types, abi_item['inputs']):
        if typ.startswith('uint') or typ.startswith('int'):
            parsed_args.append(int(val, 0))
        elif typ == 'address':
            parsed_args.append(val)
        elif typ.startswith('bytes'):
            if val.startswith('0x'):
                parsed_args.append(bytes.fromhex(val[2:]))
            else:
                parsed_args.append(bytes.fromhex(val))
        elif typ.startswith('tuple'):
            try:
                parsed_val = ast.literal_eval(val)
                if 'components' in abi_input:
                    parsed_args.append(parse_tuple_arg(parsed_val, abi_input))
                else:
                    parsed_args.append(parsed_val)
            except Exception as e:
                print(f"Error parsing tuple argument: {val} ({e})")
                sys.exit(1)
        else:
            parsed_args.append(val)
    from eth_abi.abi import encode
    try:
        # For tuple types, we need to pass the full ABI input structure
        encoded_args = encode(func_types, parsed_args)
    except Exception as e:
        print(f'Error encoding arguments: {e}')
        sys.exit(1)
    
    # Calculate function selector (first 4 bytes of keccak256 hash of function signature)
    from eth_hash.auto import keccak
    function_signature = f"{func_name}({','.join(func_types)})"
    selector = keccak(function_signature.encode())[:4]
    
    # Combine selector with encoded arguments
    calldata = "0x" + selector.hex() + encoded_args.hex()
    
    # Prepare call_obj
    call_obj = {
        'to': args.contract_address,
        'from': args.from_addr,
        'data': calldata,
        'value': args.value
    }
    trace_config = {"disableStorage": False, "disableMemory": False}
    if args.tx_index is not None:
        trace_config["txIndex"] = args.tx_index
    block = args.block
    # Simulate call
    trace = tracer.simulate_call_trace(
        args.contract_address, args.from_addr, calldata, block, args.tx_index, args.value
    )
    function_calls = tracer.analyze_function_calls(trace)
    if getattr(args, 'json', False):
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
    else:
        tracer.print_function_trace(trace, function_calls)
    return 0

def debug_command(args):
    """Execute the debug command."""
    contract_address = None
    ethdebug_dir = None
    abi_path = None
    session = None
    if args.contract_file:
        try:
            session = AutoDeployDebugger(
                contract_file=args.contract_file,
                rpc_url=args.rpc,
                constructor_args=getattr(args, 'constructor_args', []),
                solc_path=args.solc_path,
                dual_compile=args.dual_compile,
                keep_build=args.keep_build,
                output_dir=args.output_dir,
                production_dir=args.production_dir,
                json_output=args.json,
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
            contract_address = session.contract_address
            ethdebug_dir = str(session.debug_dir)
            abi_path = str(session.abi_path)
            
        except Exception as e:
            print(error(f"Debug session failed: {e}"))
            return 1
    elif args.contract_address:
        if not args.ethdebug_dir:
            print(error("Error: --ethdebug-dir is required when using --contract-address."))
            return 1
        if args.constructor_args:
            print(error("Warning: --constructor-args ignored when using --contract-address (contract is already deployed)."))
        contract_address = args.contract_address
        ethdebug_dir = args.ethdebug_dir
    else:
        print(error("Either --contract-file or --contract-address required"))
        return 1
            
    print("\nStarting debugger...")
    debugger = EVMDebugger(
        contract_address=str(contract_address),
        rpc_url=(session.rpc_url if session else args.rpc),
        ethdebug_dir=ethdebug_dir,
        function_name=getattr(args, 'function', None),
        function_args=getattr(args, 'args', []),
        command_debug=True,
        abi_path=abi_path
    )

    # Baseline snapshot (unless disabled)
    if not args.no_snapshot:
        debugger.tracer.snapshot_state()

    debugger._do_interactive()

    try:
        debugger.cmdloop()
        
        if args.fork_url and session and not args.keep_fork:
            session.cleanup()
    except KeyboardInterrupt:
        print("\nInterrupted")
        if args.fork_url and session and not args.keep_fork:
            print("Stopping anvil fork...")
            session.cleanup()
        return 1
    
    return 0

def main():
    parser = argparse.ArgumentParser(description='SolDB - Ethereum transaction analysis tool')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 0.1.0')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True
    
    # Create the 'debug' subcommand for standalone interactive debugging
    debug_parser = subparsers.add_parser('debug', help='Compile, deploy, and debug a contract, or attach to an existing one.')
    debug_parser.add_argument('--rpc', '-r', default='http://localhost:8545', help='RPC URL')

    # Use a mutually exclusive group to ensure user provides either a file to deploy or an address to attach to
    contract_group = debug_parser.add_mutually_exclusive_group(required=True)
    contract_group.add_argument('--contract-file', '-c', help='Path to Solidity source file to auto-compile and deploy.')
    contract_group.add_argument('--contract-address', help='Address of an already deployed contract to attach to.')
    debug_parser.add_argument('--ethdebug-dir', '-e', help='ETHDebug directory (required if using --contract-address)')
    debug_parser.add_argument('--function', '-f', help='Function to simulate on start.')
    debug_parser.add_argument('--args', nargs='*', default=[], help='A list of arguments for the function.')
    debug_parser.add_argument('--constructor-args', nargs='*', default=[], help='Constructor arguments (only used with --contract-file)')
    debug_parser.add_argument('--solc-path', '-solc', default='solc', help='Path to solc binary (default: solc)')
    debug_parser.add_argument('--dual-compile', action='store_true', help='Create both optimized production and debug builds')
    debug_parser.add_argument('--keep-build', action='store_true', help='Keep build directory after compilation (default: False)')
    debug_parser.add_argument('--output-dir', '-o', default='./build/debug/ethdebug', help='Output directory for ETHDebug files (default: ./build/debug/ethdebug)')
    debug_parser.add_argument('--production-dir', default='./build/contracts', help='Production directory for compiled contracts (default: ./build/contracts)')
    debug_parser.add_argument('--json', action='store_true', help='Output results as JSON')
    debug_parser.add_argument('--save-config', action='store_true', help='Save configuration to walnut.config.yaml')
    debug_parser.add_argument('--verify-version', action='store_true', help='Verify solc version supports ETHDebug and exit')
    debug_parser.add_argument('--no-cache', action='store_true', default=False, help='Enable deployment cache')
    debug_parser.add_argument('--cache-dir', default='.walnut_cache', help='Cache directory')
    debug_parser.add_argument('--fork-url', help='Upstream RPC URL to fork (launch anvil)')
    debug_parser.add_argument('--fork-block', type=int, help='Specific block number to fork')
    debug_parser.add_argument('--fork-port', type=int, default=8545, help='Local fork port (default: 8545)')
    debug_parser.add_argument('--keep-fork', action='store_true', help='Do not terminate the forked node on exit')
    debug_parser.add_argument('--reuse-fork', action='store_true', help='Reuse an existing local fork if available on --fork-port')
    debug_parser.add_argument('--no-snapshot', action='store_true',default=False, help='Disable automatic initial snapshot')
    
    # Create the 'trace' subcommand
    trace_parser = subparsers.add_parser('trace', help='Trace and debug an Ethereum transaction')
    trace_parser.add_argument('tx_hash', help='Transaction hash to trace')
    # trace_parser.add_argument('--debug-info-from-zasm-file', '-d', help='Load debug info from .zasm file (solx/evm-dwarf format)')
    trace_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: [address:]path or just path')
    trace_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    trace_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')
    trace_parser.add_argument('--rpc', '-r', default='http://localhost:8545', help='RPC URL')
    trace_parser.add_argument('--max-steps', '-m', type=int, default=50, help='Maximum steps to show (use 0 or -1 for all steps)')
    trace_parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive debugger')
    trace_parser.add_argument('--raw', action='store_true', help='Show raw instruction trace instead of function call trace')
    trace_parser.add_argument('--json', action='store_true', help='Output trace data as JSON for web app consumption')
    
    # Create the 'simulate' subcommand
    simulate_parser = subparsers.add_parser('simulate', help='Simulate and debug an Ethereum transaction')
    simulate_parser.add_argument('contract_address', help='Contract address (0x...)')
    simulate_parser.add_argument('function_signature', nargs='?', help='Function signature, e.g. increment(uint256)')
    simulate_parser.add_argument('function_args', nargs='*', help='Arguments for the function')
    simulate_parser.add_argument('--from', dest='from_addr', required=True, help='Sender address')
    simulate_parser.add_argument('--block', type=int, default=None, help='Block number or tag (default: latest)')
    simulate_parser.add_argument('--tx-index', type=int, default=None, help='Transaction index in block (optional)')
    simulate_parser.add_argument('--value', type=int, default=0, help='ETH value to send (in wei)')
    simulate_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: [address:]path or just path')
    simulate_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    simulate_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')
    simulate_parser.add_argument('--rpc-url', default='http://localhost:8545', help='RPC URL')
    simulate_parser.add_argument('--json', action='store_true', help='Output trace data as JSON for web app consumption')
    simulate_parser.add_argument('--raw-data', dest='raw_data', default=None, help='Raw calldata to send (hex string, 0x...)')
    
    args = parser.parse_args()
    
    # Handle commands
    if args.command == 'debug':
        return debug_command(args)
    elif args.command == 'trace':
        return trace_command(args)
    elif args.command == 'simulate':
        return simulate_command(args)
        
    return 0

if __name__ == '__main__':
    sys.exit(main())
