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

from web3 import HTTPProvider

from .transaction_tracer import TransactionTracer, SourceMapper
from .evm_repl import EVMDebugger
from .abi_utils import match_abi_types, match_single_type, parse_signature, parse_tuple_arg
from .multi_contract_ethdebug_parser import MultiContractETHDebugParser
from .json_serializer import TraceSerializer
from .colors import error, info, warning
from .auto_deploy import AutoDeployDebugger
from .ethdebug_dir_parser import ETHDebugDirParser, ETHDebugSpec
from eth_utils.address import is_address
from .utils import print_contracts_in_transaction,print_contracts_events


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
    
    # Show RPC URL being used
    if not args.json:
        print(f"Connecting to RPC: {info(args.rpc)}")
    
    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc, quiet_mode=args.json)
    except ConnectionError as e:
        print(f"{error(e)}")
        return 1
    
    # Trace transaction
    if not args.json:
        print(f"Loading transaction {info(args.tx_hash)}...")
        sys.stdout.flush()  # Ensure output order
    
    try:
        trace = tracer.trace_transaction(args.tx_hash)
    except ValueError as e:
        print(f"{error(e)}")
        return 1
    
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
            try:
                # Parse all ethdebug directories at once
                specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
                
                for spec in specs:
                    if spec.address and spec.name:
                        # Single contract format: address:name:path
                        multi_parser.load_contract(spec.address, spec.path, spec.name)
                    elif spec.address:
                        # Multi-contract format: address:path
                        multi_parser.load_contract(spec.address, spec.path)
                    else:
                        # Just path - try to load from deployment.json
                        deployment_file = Path(spec.path) / "deployment.json"
                        if deployment_file.exists():
                            multi_parser.load_from_deployment(deployment_file)
                        else:
                            print(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
            except ValueError as e:
                print(f"Error parsing ethdebug directories: {e}")
                return 1
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
        # Single contract mode - parse address:name:path format (required)
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
            if not specs:
                print(error("No valid ethdebug directory specified"))
                return 1
            spec = specs[0]
            address, name, ethdebug_dir = spec.address, spec.name, spec.path
        except ValueError as e:
            print(error(f"Error: {e}"))
            return 1
        
        # Load ETHDebug info for non-interactive mode only
        if not args.interactive:
            source_map = tracer.load_ethdebug_info(ethdebug_dir, name)
            # Try to load ABI from ethdebug directory
            contract_name = tracer.ethdebug_info.contract_name if tracer.ethdebug_info else None
            abi_path = ETHDebugDirParser.find_abi_file(spec, contract_name)
            if abi_path:
                tracer.load_abi(abi_path)
        else:
            # For interactive mode, ETHDebug info will be loaded by EVMDebugger
            source_map = {}
        
        # After loading the trace, check if we need to load additional contract debug info
        # This allows single contract mode to work with multi-contract scenarios
        if not args.interactive:
            # Analyze the trace to find additional contracts that need debug info
            function_calls = tracer.analyze_function_calls(trace)
            
            # Create a multi-contract parser to handle additional contracts
            multi_parser = MultiContractETHDebugParser()
            
            # Add the already loaded contract
            if tracer.ethdebug_info:
                multi_parser.load_contract(address, ethdebug_dir, name)
            
            # Load ABIs for ALL contracts that might be called during trace
            for addr, contract_info in multi_parser.contracts.items():
                abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                if abi_path.exists():
                    tracer.load_abi(str(abi_path))
            
            # Set the multi-contract parser
            tracer.multi_contract_parser = multi_parser
        else:
            # For interactive mode, also create multi-contract parser and load ABIs
            # This ensures ABI is available for parameter decoding
            multi_parser = MultiContractETHDebugParser()
            
            # Add the already loaded contract
            if tracer.ethdebug_info:
                multi_parser.load_contract(address, ethdebug_dir, name)
            
            # Load ABIs for ALL contracts that might be called during trace
            for addr, contract_info in multi_parser.contracts.items():
                abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                if abi_path.exists():
                    tracer.load_abi(str(abi_path))
            
            # Set the multi-contract parser
            tracer.multi_contract_parser = multi_parser
            print(f"Multi-contract parser set: {tracer.multi_contract_parser}")
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
        # Determine the correct ethdebug_dir for the entrypoint contract
        entrypoint_ethdebug_dir = None
        if tracer.multi_contract_parser and trace.to_addr:
            # In multi-contract mode, find the ethdebug_dir for the entrypoint contract
            entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(trace.to_addr)
            if entrypoint_contract:
                entrypoint_ethdebug_dir = str(entrypoint_contract.debug_dir)
        elif args.ethdebug_dir:
            # In single contract mode, parse the ethdebug_dir format and extract path
            try:
                specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
                if specs:
                    entrypoint_ethdebug_dir = specs[0].path
                else:
                    entrypoint_ethdebug_dir = args.ethdebug_dir[0]
            except ValueError:
                # Fallback to old parsing for backward compatibility
                ethdebug_spec = args.ethdebug_dir[0]
                if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                    parts = ethdebug_spec.split(':', 2)
                    if len(parts) >= 3:
                        entrypoint_ethdebug_dir = parts[2]  # Extract path part
                    elif len(parts) == 2:
                        entrypoint_ethdebug_dir = parts[1]  # Extract path part
                    else:
                        entrypoint_ethdebug_dir = ethdebug_spec
                else:
                    entrypoint_ethdebug_dir = ethdebug_spec
        
        # Extract contract name from the entrypoint contract
        contract_name = None
        abi_path = None
        
        if tracer.multi_contract_parser and trace.to_addr:
            # In multi-contract mode, get the name from the entrypoint contract
            entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(trace.to_addr)
            if entrypoint_contract:
                contract_name = entrypoint_contract.name
        elif args.ethdebug_dir:
            # In single contract mode, extract from ethdebug_dir
            try:
                specs = ETHDebugDirParser.parse_ethdebug_dirs(args.ethdebug_dir)
                if specs:
                    contract_name = specs[0].name
                else:
                    contract_name = None
            except ValueError:
                # Fallback to old parsing for backward compatibility
                ethdebug_spec = args.ethdebug_dir[0]
                if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                    parts = ethdebug_spec.split(':', 2)
                    if len(parts) >= 3:
                        contract_name = parts[1]  # Extract name part
        
        debugger = EVMDebugger(
            contract_address=trace.to_addr,
            debug_file=debug_file,
            rpc_url=args.rpc,
            ethdebug_dir=entrypoint_ethdebug_dir,
            tracer=tracer,
            contract_name=contract_name,
            abi_path=abi_path
        )
        
        # Pre-load the trace and function analysis
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

def list_contracts_command(args):
    """Execute the list-events command."""

    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except ConnectionError as e:
        print(f"{error(e)}")
        return 1

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
            try:
                # Parse all ethdebug directories at once
                specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)

                for spec in specs:
                    if spec.address and spec.name:
                        # Single contract format: address:name:path
                        multi_parser.load_contract(spec.address, spec.path, spec.name)
                    elif spec.address:
                        # Multi-contract format: address:path
                        multi_parser.load_contract(spec.address, spec.path)
                    else:
                        # Just path - try to load from deployment.json
                        deployment_file = Path(spec.path) / "deployment.json"
                        if deployment_file.exists():
                            try:
                                multi_parser.load_from_deployment(deployment_file)
                            except Exception as e:
                                sys.stderr.write(f"Error loading deployment.json from {spec.path}: {e}\n")
                                sys.exit(1)
                        else:
                            sys.stderr.write(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
            except ValueError as e:
                sys.stderr.write(f"Error parsing ethdebug directories: {e}\n")
                sys.exit(1)

        for addr, contract_info in multi_parser.contracts.items():
            abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
            if abi_path.exists():
                tracer.load_abi(str(abi_path))
            elif (contract_info.debug_dir / f"{contract_info.name}.json").exists():
                tracer.load_abi(str(contract_info.debug_dir / f"{contract_info.name}.json"))

        tracer.multi_contract_parser = multi_parser

    # Get transaction trace
    try:
        trace = tracer.trace_transaction(args.tx_hash)
    except ValueError as e:
        print(f"{error(e)}")
        return 1
    # Print contracts involved in the transaction
    print_contracts_in_transaction(tracer,trace)
    return 0
          
def simulate_command(args):
    """Execute the simulate command."""

    # If --raw-data is provided, do not provide function_signature or function_args
    if getattr(args, 'raw_data', None):
        if getattr(args, 'function_signature', None) or (hasattr(args, 'function_args') and args.function_args):
            print("Error: When using --raw-data, do not provide function_signature or function_args.")
            sys.exit(1)

    # Show RPC URL being used
    if not getattr(args, 'json', False):
        print(f"Connecting to RPC: {info(args.rpc_url)}")

    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except ConnectionError as e:
        print(f"{error(e)}")
        return 1
    source_map = {}

    if args.contract_address and not args.interactive:
        if not is_address(args.contract_address):
            print(error(f'Contract not found: {args.contract_address}'))
            print("Please verify:")
            print("  - The address is correct")
            print("  - You're connected to the right network and your contract is deployed")
            sys.exit(1)
        
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
            try:
                # Parse all ethdebug directories at once
                specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
                
                for spec in specs:
                    if spec.address and spec.name:
                        # Single contract format: address:name:path
                        multi_parser.load_contract(spec.address, spec.path, spec.name)
                    elif spec.address:
                        # Multi-contract format: address:path
                        multi_parser.load_contract(spec.address, spec.path)
                    else:
                        # Just path - try to load from deployment.json
                        deployment_file = Path(spec.path) / "deployment.json"
                        if deployment_file.exists():
                            try:
                                multi_parser.load_from_deployment(deployment_file)
                            except Exception as e:
                                sys.stderr.write(f"Error loading deployment.json from {spec.path}: {e}\n")
                                sys.exit(1)
                        else:
                            sys.stderr.write(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
            except ValueError as e:
                sys.stderr.write(f"Error parsing ethdebug directories: {e}\n")
                sys.exit(1)
        tracer.multi_contract_parser = multi_parser

        # Set primary contract context for simulation (entrypoint contract)
        primary_contract = multi_parser.get_contract_at_address(args.contract_address)
        if primary_contract:
            # We have debug info for the entrypoint contract
            tracer.ethdebug_parser = primary_contract.parser
            tracer.ethdebug_parser.debug_dir = str(primary_contract.debug_dir)  # Set debug_dir for source loading
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
        else:
            # No debug info for entrypoint contract - simulate without source mapping
            # This is similar to how trace command works
            source_map = {}
            if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
                print(warning(f"Warning: No ETHDebug information for entrypoint contract {args.contract_address}"))
                print(f"Simulation will work but function calls may not be properly decoded.")
                print(f"For better debugging experience, provide ETHDebug information using:")
                print(f"  --ethdebug-dir {args.contract_address}:ContractName:path/to/debug/dir")
                print()
            
            # Try to load ABI for entrypoint contract from common locations
            if args.contract_address:
                # Try to find ABI in current directory
                for abi_file in Path(".").glob("*.abi"):
                    tracer.load_abi(str(abi_file))
                    break
        # Load ABIs for ALL contracts that might be called during simulation
        for addr, contract_info in multi_parser.contracts.items():
            abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
            if abi_path.exists():
                tracer.load_abi(str(abi_path))
                
    elif ethdebug_dirs and not multi_contract_mode:
        # Single contract mode - parse address:name:path format (required)
        try:
            specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
            if not specs:
                print(error("No valid ethdebug directory specified"))
                sys.exit(1)
            spec = specs[0]
            address, name, ethdebug_dir = spec.address, spec.name, spec.path
        except ValueError as e:
            print(error(f"Error: {e}"))
            sys.exit(1)
        
        # Check if the contract address matches the ETHDebug address
        if args.contract_address and args.contract_address.lower() != address.lower():
            # Address doesn't match - simulate without source mapping for entrypoint
            # This is similar to how trace command works
            source_map = {}
            if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
                print(warning(f"Warning: Contract address {args.contract_address} does not match ETHDebug address {address}"))
                print(f"Simulation will work but function calls may not be properly decoded.")
                print(f"For better debugging experience, use the correct address:")
                print(f"  --ethdebug-dir {args.contract_address}:ContractName:path/to/debug/dir")
                print()
            
            # Load ETHDebug info for the specified contract (even though it's not entrypoint)
            if not args.interactive:
                tracer.load_ethdebug_info(ethdebug_dir, name)
                if tracer.ethdebug_info:
                    abi_path = os.path.join(ethdebug_dir, f"{tracer.ethdebug_info.contract_name}.abi")
                    if os.path.exists(abi_path):
                        tracer.load_abi(abi_path)
                else:
                    for abi_file in Path(ethdebug_dir).glob("*.abi"):
                        tracer.load_abi(str(abi_file))
                        break
            
            # Try to load ABI for entrypoint contract from common locations
            if args.contract_address:
                # Try to find ABI in current directory
                for abi_file in Path(".").glob("*.abi"):
                    tracer.load_abi(str(abi_file))
                    break
        else:
            # Address matches - load debug info for non-interactive mode only
            if not args.interactive:
                source_map = tracer.load_ethdebug_info(ethdebug_dir, name)
                contract_name = tracer.ethdebug_info.contract_name if tracer.ethdebug_info else None
                abi_path = ETHDebugDirParser.find_abi_file(spec, contract_name)
                if abi_path:
                    tracer.load_abi(abi_path)
            else:
                source_map = {}
        
        # Create a multi-contract parser to handle additional contracts (same as trace command)
        multi_parser = MultiContractETHDebugParser()
        
        # Add the already loaded contract
        if tracer.ethdebug_info:
            multi_parser.load_contract(address, ethdebug_dir, name)
        
        # Load ABIs for ALL contracts that might be called during simulation
        for addr, contract_info in multi_parser.contracts.items():
            abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
            if abi_path.exists():
                tracer.load_abi(str(abi_path))
        
        # Set the multi-contract parser
        tracer.multi_contract_parser = multi_parser
    else:
        # No debug info provided - simulate without source code
        # Try to load ABI from common locations if available
        if args.contract_address:
            # Try to find ABI in current directory
            for abi_file in Path(".").glob("*.abi"):
                tracer.load_abi(str(abi_file))
                break
    if args.interactive:
        # Start interactive debugger
        interactive_mode(args,tracer)
        return 0
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
        elif getattr(args, 'raw', False):
            tracer.print_trace(trace, source_map, args.max_steps)
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
    # Check if we have any ABI loaded
    has_abi = len(tracer.function_abis) > 0
    
    if has_abi and not abi_item:
        print(f'Function {args.function_signature} not found in ABI')
        available_functions = [item["name"] for item in tracer.function_abis.values()]
        if available_functions:
            print(f'Available functions: {available_functions}')
        else:
            print('No functions found in any loaded ABI files.')
        print('Proceeding with function signature parsing...')
        # Don't exit - continue with function signature parsing
    
    # If no ABI available, we can still proceed with function signature parsing
    if not has_abi:
        print(f'No ABI files found. Proceeding with function signature: {args.function_signature}')
        print('Note: Parameter validation will be based on function signature types only.')
    # Parse function_args from CLI to correct types
    if has_abi and abi_item:
        # Use ABI for type information
        input_types = [inp['type'] for inp in abi_item['inputs']]
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
    else:
        # No ABI available - parse arguments based on function signature types
        if len(args.function_args) != len(func_types):
            print(f'Function {args.function_signature} expects {len(func_types)} arguments, got {len(args.function_args)}')
            sys.exit(1)
        
        parsed_args = []
        for val, typ in zip(args.function_args, func_types):
            if typ.startswith('uint') or typ.startswith('int'):
                parsed_args.append(int(val, 0))
            elif typ == 'address':
                parsed_args.append(val)
            elif typ.startswith('bytes'):
                if val.startswith('0x'):
                    parsed_args.append(bytes.fromhex(val[2:]))
                else:
                    parsed_args.append(bytes.fromhex(val))
            elif typ == 'string':
                parsed_args.append(val)
            elif typ == 'bool':
                parsed_args.append(val.lower() in ('true', '1', 'yes'))
            else:
                # For unknown types, try to parse as string
                parsed_args.append(val)
    from eth_abi.abi import encode
    try:
        # Use func_types for encoding (works with or without ABI)
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
    
    # Analyze function calls with the loaded debug info
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
    elif getattr(args, 'raw', False):
        tracer.print_trace(trace, source_map, args.max_steps)
    else:
        tracer.print_function_trace(trace, function_calls)
    return 0

def interactive_mode(args,tracer):
    """Execute the debug command."""
    contract_address = None
    ethdebug_dir = None
    abi_path = None
    session = None

     # Validate required arguments when in interactive mode
    if not getattr(args, 'contract_address', None):
        print('Error: contract address is required')
        sys.exit(1)

    # Detect whether on the contract address position is an address or a file path
    contract_arg = args.contract_address
    is_contract_file = False
    is_contract_address = False

    # Check if it's a file path (exists and ends with .sol)
    if os.path.exists(contract_arg) and contract_arg.endswith('.sol'):
        is_contract_file = True
        args.contract_file = contract_arg
    # Check if it's an Ethereum address (starts with 0x and right length)
    elif contract_arg.startswith('0x'):
            if is_address(contract_arg):
                is_contract_address = True
                args.contract_address = contract_arg
            else:
                print(error(f'Contract not found: {contract_arg}'))
                print("Please verify:")
                print("  - The address is correct")
                print("  - You're connected to the right network and your contract is deployed")
                sys.exit(1)
    else:
        print(error(f'Contract not found: {contract_arg}'))
        print("Please verify:")
        print("  - The address is correct")
        print("  - You're connected to the right network and your contract is deployed")
        sys.exit(1)

    if not getattr(args, 'function_signature', None):
        print('Error: function signature is required')
        sys.exit(1)

    contract_name = None
    if is_contract_file:
        try:
            session = AutoDeployDebugger(
                contract_file=args.contract_file,
                rpc_url=args.rpc_url,
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
    elif is_contract_address:
        if not args.ethdebug_dir and not args.contracts:
            print(error("Error: --ethdebug-dir is required when using --contract-address."))
            return 1
        if args.constructor_args:
            print(error("Warning: --constructor-args ignored when using --contract-address (contract is already deployed)."))
        contract_address = args.contract_address
        # Determine the correct ethdebug_dir for the entrypoint contract
        contract_name = None
        if getattr(tracer, 'multi_contract_parser', None):
            # In multi-contract mode, find the ethdebug_dir for the entrypoint contract
            entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(args.contract_address)
            if entrypoint_contract:
                ethdebug_dir = str(entrypoint_contract.debug_dir)
                contract_name = entrypoint_contract.name
                print(f"Interactive mode {entrypoint_contract.name}")
            else:
                # Fallback to first ethdebug_dir if entrypoint not found - parse format
                ethdebug_spec = args.ethdebug_dir[0] if isinstance(args.ethdebug_dir, list) else args.ethdebug_dir
                try:
                    specs = ETHDebugDirParser.parse_ethdebug_dirs([ethdebug_spec])
                    if specs:
                        ethdebug_dir = specs[0].path
                        contract_name = specs[0].name
                    else:
                        ethdebug_dir = ethdebug_spec
                        contract_name = None
                except ValueError:
                    # Fallback to old parsing for backward compatibility
                    if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                        parts = ethdebug_spec.split(':', 2)
                        if len(parts) >= 3:
                            ethdebug_dir = parts[2]  # Extract path part
                            contract_name = parts[1]  # Extract name part
                        elif len(parts) == 2:
                            ethdebug_dir = parts[1]  # Extract path part
                        else:
                            ethdebug_dir = ethdebug_spec
                    else:
                        ethdebug_dir = ethdebug_spec
        else:
            # Single contract mode - parse format
            ethdebug_spec = args.ethdebug_dir[0] if isinstance(args.ethdebug_dir, list) else args.ethdebug_dir
            try:
                specs = ETHDebugDirParser.parse_ethdebug_dirs([ethdebug_spec])
                if specs:
                    ethdebug_dir = specs[0].path
                    contract_name = specs[0].name
                else:
                    ethdebug_dir = ethdebug_spec
                    contract_name = None
            except ValueError:
                # Fallback to old parsing for backward compatibility
                if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                    parts = ethdebug_spec.split(':', 2)
                    if len(parts) >= 3:
                        ethdebug_dir = parts[2]  # Extract path part
                        contract_name = parts[1]  # Extract name part
                    elif len(parts) == 2:
                        ethdebug_dir = parts[1]  # Extract path part
                    else:
                        ethdebug_dir = ethdebug_spec
                else:
                    ethdebug_dir = ethdebug_spec
    else:
        print(error("Either --contract-file or --contract-address required"))
        return 1

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
        contract_name=contract_name
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

def list_events_command(args):
    """Execute the list-events command."""

    # Create tracer
    try:
        tracer = TransactionTracer(args.rpc_url)
    except ConnectionError as e:
        print(f"{error(e)}")
        return 1

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
            try:
                # Parse all ethdebug directories at once
                specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
                
                for spec in specs:
                    if spec.address and spec.name:
                        # Single contract format: address:name:path
                        multi_parser.load_contract(spec.address, spec.path, spec.name)
                    elif spec.address:
                        # Multi-contract format: address:path
                        multi_parser.load_contract(spec.address, spec.path)
                    else:
                        # Just path - try to load from deployment.json
                        deployment_file = Path(spec.path) / "deployment.json"
                        if deployment_file.exists():
                            try:
                                multi_parser.load_from_deployment(deployment_file)
                            except Exception as e:
                                sys.stderr.write(f"Error loading deployment.json from {spec.path}: {e}\n")
                                sys.exit(1)
                        else:
                            sys.stderr.write(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
            except ValueError as e:
                sys.stderr.write(f"Error parsing ethdebug directories: {e}\n")
                sys.exit(1)

        for addr, contract_info in multi_parser.contracts.items():
            abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
            if abi_path.exists():
                tracer.load_abi(str(abi_path))
            elif (contract_info.debug_dir / f"{contract_info.name}.json").exists():
                tracer.load_abi(str(contract_info.debug_dir / f"{contract_info.name}.json"))

        tracer.multi_contract_parser = multi_parser

    # Get transaction receipt
    try:
        receipt = tracer.w3.eth.get_transaction_receipt(args.tx_hash)
    except Exception as e:
        print(f"{error(e)}")
        return 1
    
    # Decode and print events
    print_contracts_events(tracer,receipt)
    return 0

def main():
    parser = argparse.ArgumentParser(description='SolDB - Ethereum transaction analysis tool')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 0.1.0')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True

    list_parser = subparsers.add_parser('list-contracts', help='List all contracts in the project')
    list_parser.add_argument('tx_hash', help='Transaction hash to list contracts for')
    list_parser.add_argument('--rpc-url', '-r', default='http://localhost:8545', help='RPC URL')
    list_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: [address:]path or just path')
    list_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    list_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')

    event_parser = subparsers.add_parser('list-events', help='Decode and display events from transaction logs')
    event_parser.add_argument('tx_hash', help='Transaction hash to decode events from')
    event_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: address:name:path')
    event_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    event_parser.add_argument('--rpc-url', '-r', default='http://localhost:8545', help='RPC URL')
    event_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract decoding mode')

    # Create the 'trace' subcommand
    trace_parser = subparsers.add_parser('trace', help='Trace and debug an Ethereum transaction')
    trace_parser.add_argument('tx_hash', help='Transaction hash to trace')
    # trace_parser.add_argument('--debug-info-from-zasm-file', '-d', help='Load debug info from .zasm file (solx/evm-dwarf format)')
    trace_parser.add_argument('--ethdebug-dir', '-e', action='append', help='ETHDebug directory containing ethdebug.json and contract debug files. Can be specified multiple times for multi-contract debugging. Format: address:name:path')
    trace_parser.add_argument('--contracts', '-c', help='JSON file mapping contract addresses to debug directories')
    trace_parser.add_argument('--multi-contract', action='store_true', help='Enable multi-contract debugging mode')
    trace_parser.add_argument('--rpc', '-r', default='http://localhost:8545', help='RPC URL')
    trace_parser.add_argument('--max-steps', '-m', type=int, default=50, help='Maximum steps to show (use 0 or -1 for all steps)')
    trace_parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive debugger')
    trace_parser.add_argument('--raw', action='store_true', help='Show raw instruction trace instead of function call trace')
    trace_parser.add_argument('--json', action='store_true', help='Output trace data as JSON for web app consumption')
    
    # Create the 'simulate' subcommand
    simulate_parser = subparsers.add_parser('simulate', help='Simulate and debug an Ethereum transaction')
    simulate_parser.add_argument('--from', dest='from_addr', required=True, help='Sender address')
    simulate_parser.add_argument('--interactive', '-i', action='store_true', help='Start interactive debugger after simulation')

    # Single positional argument that can be either contract address or contract file
    simulate_parser.add_argument('contract_address', help='Contract address (0x...)')
    simulate_parser.add_argument('function_signature', nargs='?', help='Function signature, e.g. increment(uint256)')
    simulate_parser.add_argument('function_args', nargs='*', help='Arguments for the function')
    simulate_parser.add_argument('--block', type=int, default=None, help='Block number or tag (default: latest)')
    simulate_parser.add_argument('--tx-index', type=int, default=None, help='Transaction index in block (optional)')
    simulate_parser.add_argument('--value', type=int, default=0, help='ETH value to send (in wei)')
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
    simulate_parser.add_argument('--no-snapshot', action='store_true',default=False, help='Disable automatic initial snapshot')
    
    args = parser.parse_args()
    
    # Handle commands
    if args.command == 'trace':
        return trace_command(args)
    if args.command == 'simulate':
        return simulate_command(args)
    if args.command == 'list-events':
        return list_events_command(args)

    if args.command == 'list-contracts':
        return list_contracts_command(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
