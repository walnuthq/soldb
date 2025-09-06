"""
EVM REPL Debugger

Interactive REPL for debugging EVM transactions with source mapping.
"""

import cmd
import os
import json
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from .transaction_tracer import TransactionTracer, TransactionTrace, SourceMapper
from .dwarf_parser import load_dwarf_info, DwarfParser
from .ethdebug_dir_parser import ETHDebugDirParser, ETHDebugSpec
from .colors import *
from web3 import Web3

class EVMDebugger(cmd.Cmd):
    """Interactive EVM debugger REPL."""
    
    intro = f"""
{bold('SolDB EVM Debugger')} - Solidity Debugger
Type {info('help')} for commands.
Use {info('next')}/{info('nexti')} to step, {info('continue')} to run, {info('where')} to see call stack.
"""
    prompt = f'{cyan("(soldb)")} '
    
    def __init__(self, contract_address: str = None, debug_file: str = None, 
                 rpc_url: str = "http://localhost:8545", ethdebug_dir: str = None, constructor_args: List[str] = [],
                 multi_contract_parser = None,function_name: str = None, function_args: List[str] = [],
                 abi_path: str = None, from_addr: str = None, block: int = None,
                 tracer: TransactionTracer = None, contract_name: str = None):
        super().__init__()

        if not tracer:
            tracer = TransactionTracer(rpc_url)
        
        self.tracer = tracer

        # Set multi-contract parser if provided
        if multi_contract_parser:
            self.tracer.multi_contract_parser = multi_contract_parser
            # In multi-contract mode, set ethdebug_info to the main contract
            if contract_address:
                main_contract = multi_contract_parser.get_contract_at_address(contract_address)
                if main_contract:
                    self.tracer.ethdebug_info = main_contract.ethdebug_info
                    self.tracer.ethdebug_parser = main_contract.parser
                    # Load source_map from the main contract
                    self.source_map = main_contract.parser.get_source_mapping() if main_contract.parser else {}
                    
                    # Load ABI for the main contract using ETHDebugDirParser
                    abi_path = ETHDebugDirParser.find_abi_file(
                        ETHDebugSpec(path=str(main_contract.debug_dir)), 
                        main_contract.name
                    )
                    if abi_path:
                        self.tracer.load_abi(abi_path)
                else:
                    # No debug info for this contract
                    self.source_map = {}
        self.current_trace = None
        self.current_step = 0
        self.breakpoints = set()
        self.watch_expressions = []
        self.display_mode = "source"  # "source" or "asm"
        self.function_trace = []  # Function call trace
        self.variable_history = {}  # variable_name -> list of (step, value, type, location)
        
        # Variable display filters
        self.variable_filters = {
            'show_types': set(),  # If empty, show all types
            'hide_types': set(),  # Specific types to hide
            'show_locations': set(),  # If empty, show all locations
            'hide_locations': set(),  # Specific locations to hide
            'name_pattern': None,  # Regex pattern for variable names
            'hide_parameters': False,  # Hide function parameters
            'hide_temporaries': True,  # Hide compiler-generated temporary variables
        }
        
        # Load contract and debug info
        self.contract_address = contract_address
        self.constructor_args = constructor_args or []
        self.debug_file = debug_file
        self.rpc_url = rpc_url
        self.ethdebug_dir = ethdebug_dir
        self.source_map = {}
        self.source_mapper = None
        self.dwarf_info = None
        self.source_lines = {}  # filename -> lines
        self.current_function = None  # Current function context
        self.function_name = function_name
        self.function_args = function_args
        self.init = False
        self.abi_path = abi_path
        self.from_addr = from_addr
        self.block = block
        self.contract_name = contract_name

        if self.contract_address and not self.tracer.is_contract_deployed(self.contract_address):
            print(error(f"Error: No contract found at address {self.contract_address}"))
            sys.exit(1)

        # Load ETHDebug info if available
        if ethdebug_dir and not multi_contract_parser:
            # Use provided contract_name or extract from ethdebug_dir if in address:name:path format
            if not self.contract_name and ":" in ethdebug_dir and ethdebug_dir.startswith("0x"):
                try:
                    spec = ETHDebugDirParser.parse_single_contract(ethdebug_dir)
                    self.contract_name = spec.name
                    ethdebug_dir = spec.path
                except ValueError:
                    # Fallback to old parsing for backward compatibility
                    parts = ethdebug_dir.split(":")
                    if len(parts) >= 3:
                        self.contract_name = parts[1]  # Extract name part
                        ethdebug_dir = parts[2]  # Extract path part
                    elif len(parts) == 2:
                        ethdebug_dir = parts[1]  # Extract path part
            self.source_map = self.tracer.load_ethdebug_info(ethdebug_dir, self.contract_name)
            # Load ABI from ethdebug directory
            contract_name = self.tracer.ethdebug_info.contract_name if self.tracer.ethdebug_info else None
            abi_path = ETHDebugDirParser.find_abi_file(ETHDebugSpec(path=ethdebug_dir), contract_name)
            if abi_path:
                self.tracer.load_abi(abi_path)
            
        elif debug_file:
            self.source_map = self.tracer.load_debug_info(debug_file)
            
            # Try to load DWARF debug ELF
            debug_elf = debug_file.replace('.zasm', '.debug.elf')
            if not os.path.exists(debug_elf):
                # Try in same directory with different naming
                base_name = os.path.basename(debug_file).split('.')[0].split('_')[0]
                debug_elf = os.path.join(os.path.dirname(debug_file), f"{base_name}.debug.elf")
            
            if os.path.exists(debug_elf):
                print(f"Loading DWARF debug info from: {info(debug_elf)}")
                self.dwarf_info = load_dwarf_info(debug_elf)
                if self.dwarf_info:
                    print(f"Loaded {success(str(len(self.dwarf_info.functions)))} functions from DWARF")
        
        # Load source files
        self._load_source_files()
        
        if contract_address:
            print(f"Contract found: {address(contract_address)}")
        
        # Only print debug mappings message if we loaded them here (not passed from main)
        if self.source_map and not ethdebug_dir:
            print(f"Loaded {success(str(len(self.source_map)))} debug mappings")
    
    def _load_source_files(self):
        """Load all source files referenced in debug info."""
        if self.tracer.ethdebug_info:
            # Load from ETHDebug sources - only load the main contract source
            main_contract_source = None
            for source_id, source_path in self.tracer.ethdebug_info.sources.items():
                # Find the main contract source (usually the one that matches contract name)
                if self.tracer.ethdebug_info.contract_name.lower() in source_path.lower():
                    main_contract_source = source_path
                    break
            
            if main_contract_source:
                lines = self.tracer.ethdebug_parser.load_source_file(main_contract_source)
                if lines:
                    self.source_lines[main_contract_source] = lines
            else:
                # Fallback: load all sources
                for source_id, source_path in self.tracer.ethdebug_info.sources.items():
                    lines = self.tracer.ethdebug_parser.load_source_file(source_path)
                    if lines:
                        self.source_lines[source_path] = lines
        elif self.debug_file:
            # Extract source file from debug file name
            source_file = self.debug_file.split('_')[0]
            if os.path.exists(source_file):
                with open(source_file, 'r') as f:
                    self.source_lines[source_file] = f.readlines()
                print(f"Loaded source: {info(source_file)}")
    
    def do_run(self, tx_hash: str):
        """Run/load a transaction for debugging. Usage: run <tx_hash>"""

        # Skip if debug session already started
        if self.init:
            return
        
        try:
            self.current_trace = self.tracer.trace_transaction(tx_hash)
            self.current_step = 0
            
            # Analyze function calls
            self.function_trace = self.tracer.analyze_function_calls(self.current_trace)
            
            print(f"{success('Transaction loaded.')} {highlight(str(len(self.current_trace.steps)))} steps.")
            
            # Start at the first function call after dispatcher
            if len(self.function_trace) > 1:
                self.current_step = self.function_trace[1].entry_step
                self.current_function = self.function_trace[1]

            self.init = True
        except Exception as e:
            print(f"{error('Error loading transaction:')} {e}")

    def _do_interactive(self):
        """Simulate a function call for debugging."""

        if not self.contract_address:
            print(f"{warning('Warning:')} No contract address set. Using default for simulation.")
            return
        else:
            contract_addr = self.contract_address

        try:
            # Parse function call
            function_name = str(self.function_name)

            function_args = f"({', '.join(self.function_args)})"
            print(f"Simulating {info(function_name.split('(')[0])}{info(function_args)}...")

            # Encode function call
            calldata = self._encode_function_call(function_name, self.function_args)
            if not calldata:
                print(f"{error('Failed to encode function call.')} Check function name and arguments.")
                return

            # Create simulation using tracer
            self.current_trace = self.tracer.simulate_call_trace(
                to=contract_addr,
                from_=self.from_addr,
                calldata=calldata,
                block=self.block
            )

            if not self.current_trace:
                print(f"{error('Simulation failed.')} Check function name and arguments.")
                return

            self.current_step = 0

            # Analyze function calls
            self.function_trace = self.tracer.analyze_function_calls(self.current_trace)
            print(f"{success('Simulation complete.')} {highlight(str(len(self.current_trace.steps)))} steps.")

            # Start at the first function call after dispatcher
            if len(self.function_trace) > 1:
                self.current_step = self.function_trace[1].entry_step
                self.current_function = self.function_trace[1]
            else:
                # If no function dispatcher, start at beginning but avoid end-of-execution
                self.current_step = 0

            self.init = True
        except Exception as e:
            print(f"{error('Error in simulation:')} {e}")
            import traceback
            print(f"{dim('Details:')} {traceback.format_exc()}")

    def _encode_function_call(self, function_name: str, args: list) -> Optional[str]:
        """Encode a function call into calldata."""
        if not hasattr(self.tracer, 'function_abis_by_name'):
            print(f"{error('No ABI information available.')}")
            return None

        # Parse function signature with optional parameter types
        original_function_name = function_name
        expected_param_types = None

        if '(' in function_name and ')' in function_name:
            # Extract function name and parameter types: "increment(uint256)" -> "increment", ["uint256"]
            base_name = function_name.split('(')[0]
            params_part = function_name.split('(')[1].split(')')[0]

            if params_part.strip():
                # Parse parameter types from brackets
                expected_param_types = [t.strip() for t in params_part.split(',')]
            else:
                expected_param_types = []  # Empty parentheses: func()

            function_name = base_name
        else:
            # Just function name without brackets
            function_name = function_name

        if function_name not in self.tracer.function_abis_by_name:
            print(f"{error('Function not found:')} {function_name}")
            if self.tracer.function_abis_by_name:
                available = list(self.tracer.function_abis_by_name.keys())
                print(f"Available functions: {', '.join(available)}")
            return None

        func_abi = self.tracer.function_abis_by_name[function_name]
        inputs = func_abi.get('inputs', [])

        # Check if function requires parameters but no brackets were provided
        if expected_param_types is None and len(inputs) > 0:
            # Function has parameters but no brackets were provided
            param_types = [inp['type'] for inp in inputs]
            print(f"{error('Function requires parameters but no signature provided.')}")
            print(f"Required signature: {function_name}({', '.join(param_types)})")
            param_str = ', '.join([f"{inp['type']} {inp['name']}" for inp in inputs])
            print(f"Full signature: {function_name}({param_str})")
            return None

        # Validate parameter types if specified in brackets
        if expected_param_types is not None:
            actual_param_types = [inp['type'] for inp in inputs]

            if len(expected_param_types) != len(actual_param_types):
                print(f"{error('Parameter count mismatch.')} Expected {len(actual_param_types)} parameters, got {len(expected_param_types)}")
                param_str = ', '.join([f"{inp['type']} {inp['name']}" for inp in inputs])
                print(f"Correct signature: {function_name}({', '.join(actual_param_types)})")
                return None

            # Check if parameter types match
            for i, (expected, actual) in enumerate(zip(expected_param_types, actual_param_types)):
                if expected != actual:
                    print(f"{error('Parameter type mismatch at position')} {i}")
                    print(f"Expected: {actual}, got: {expected}")
                    param_str = ', '.join([f"{inp['type']} {inp['name']}" for inp in inputs])
                    print(f"Correct signature: {function_name}({', '.join(actual_param_types)})")
                    return None

        # Validate argument count
        if len(args) != len(inputs):
            param_str = ', '.join([f"{inp['type']} {inp['name']}" for inp in inputs])
            print(f"{error('Argument count mismatch.')} Expected: {function_name}({param_str})")
            return None

        try:
            # Import web3 contract encoder
            from web3 import Web3

            # Convert string arguments to appropriate types
            converted_args = []
            for i, arg in enumerate(args):
                param_type = inputs[i]['type']
                converted_arg = self._convert_argument(arg, param_type)
                converted_args.append(converted_arg)

            # Create a dummy contract to encode the function call using tracer's Web3 instance
            contract = self.tracer.w3.eth.contract(abi=[func_abi])

            # Get the function and encode the call
            func = getattr(contract.functions, function_name)
            encoded = func(*converted_args).build_transaction({'to': '0x' + '0' * 40})

            return encoded['data']

        except Exception as e:
            print(f"{error('Error encoding function call:')} {e}")
            return None

    def _convert_argument(self, arg: str, param_type: str):
        """Convert string argument to appropriate type for ABI encoding."""
        if param_type.startswith('uint') or param_type.startswith('int'):
            return int(arg)
        elif param_type == 'bool':
            return arg.lower() in ('true', '1', 'yes')
        elif param_type == 'address':
            if not arg.startswith('0x'):
                arg = '0x' + arg
            return arg
        elif param_type == 'string':
            return arg
        elif param_type.startswith('bytes'):
            if not arg.startswith('0x'):
                arg = '0x' + arg
            return arg
        else:
            # For complex types, try to parse as JSON or return as string
            try:
                import json
                return json.loads(arg)
            except:
                return arg
    
    def do_nexti(self, arg):
        """Step to next instruction (instruction-level). Aliases: ni, stepi, si"""
        if not self.current_trace:
            print("No transaction loaded. Use 'run <tx_hash>' first.")
            return
        
        if self.current_step >= len(self.current_trace.steps) - 1:
            print(info("Already at end of execution."))
            return
            
        self.current_step += 1
        self._update_current_function()
        self._track_variable_changes()
        self._show_current_state()
    
    def do_ni(self, arg):
        """Alias for nexti"""
        self.do_nexti(arg)
    
    def do_stepi(self, arg):
        """Alias for nexti"""
        self.do_nexti(arg)
    
    def do_si(self, arg):
        """Alias for nexti"""
        self.do_nexti(arg)
    
    def do_next(self, arg):
        """Step to next source line (source-level). Aliases: n, step, s"""
        if not self.current_trace:
            print("No transaction loaded. Use 'run <tx_hash>' first.")
            return
        
        if self.current_step >= len(self.current_trace.steps) - 1:
            print(info("Already at end of execution."))
            return
        
        if not self.source_map:
            print("No source mapping available. Use 'nexti' for instruction stepping.")
            self.do_nexti(arg)
            return
        
        # Get current source line
        current_line = self._get_source_line_for_step(self.current_step)
        if current_line is None:
            # No source mapping, fall back to instruction stepping
            self.do_nexti(arg)
            return
        
        # Step until we reach a different source line
        initial_step = self.current_step
        while self.current_step < len(self.current_trace.steps) - 1:
            self.current_step += 1
            new_line = self._get_source_line_for_step(self.current_step)
            
            if new_line is not None and new_line != current_line:
                # Reached a new source line
                self._update_current_function()
                self._track_variable_changes()
                self._show_current_state()
                return
        
        # Reached end without finding new source line
        print(info("Already at end of execution."))
        # Reset to where we were since we didn't find a new line
        self.current_step = len(self.current_trace.steps) - 1
        self._update_current_function()
    
    def do_n(self, arg):
        """Alias for next"""
        self.do_next(arg)
    
    def do_step(self, arg):
        """Alias for next"""
        self.do_next(arg)
    
    def do_s(self, arg):
        """Alias for next"""
        self.do_next(arg)
    
    def do_continue(self, arg):
        """Continue execution until breakpoint or end. Alias: c"""
        if not self.current_trace:
            print("No transaction loaded. Use 'run <tx_hash>' first.")
            return
        
        if self.current_step >= len(self.current_trace.steps) - 1:
            print(info("Already at end of execution."))
            return
        
        initial_step = self.current_step
        while self.current_step < len(self.current_trace.steps) - 1:
            self.current_step += 1
            step = self.current_trace.steps[self.current_step]
            
            # Check breakpoints
            if step.pc in self.breakpoints:
                print(f"\n{warning('Breakpoint hit')} at PC {pc_value(step.pc)}")
                self._track_variable_changes()
                self._show_current_state()
                return
            
            # Check for errors
            if step.error:
                print(f"\nExecution error: {step.error}")
                self._show_current_state()
                return
        
        print(info("Execution completed."))
        self._track_variable_changes()
        self._show_current_state()
    
    def do_c(self, arg):
        """Alias for continue"""
        self.do_continue(arg)
    
    def do_break(self, arg):
        """Set breakpoint. Usage: break <pc> or break <file>:<line>"""
        if not arg:
            # List breakpoints
            if self.breakpoints:
                print("Breakpoints:")
                for bp in sorted(self.breakpoints):
                    print(f"  PC {bp}")
            else:
                print("No breakpoints set.")
            return
        
        if self.function_trace:
            for func in self.function_trace:
                if func.name == arg:
                    entry_pc = self.current_trace.steps[func.entry_step].pc
                    self.breakpoints.add(entry_pc)
                    print(f"Breakpoint set at function '{func.name}' (PC {entry_pc})")
                    return
                
        # Parse breakpoint
        if ':' in arg:
            # File:line format
            file_line = arg.split(':', 1)
            filename = file_line[0]
            try:
                line_num = int(file_line[1])
                # Find PC for this line
                pc_found = False
                for pc, (_, src_line) in self.source_map.items():
                    if src_line == line_num:
                        self.breakpoints.add(pc)
                        print(f"Breakpoint set at {filename}:{line_num} (PC {pc})")
                        pc_found = True
                        break
                
                if not pc_found:
                    print(f"No PC found for {filename}:{line_num}")
            except ValueError:
                print("Invalid line number")
        else:
            # PC format
            try:
                pc = int(arg, 0)  # Support hex with 0x prefix
                self.breakpoints.add(pc)
                print(f"Breakpoint set at PC {pc}")
            except ValueError:
                print("Invalid PC value")
    
    def do_clear(self, arg):
        """Clear breakpoint. Usage: clear <pc>"""
        if not arg:
            print("Usage: clear <pc>")
            return
        
        try:
            pc = int(arg, 0)
            if pc in self.breakpoints:
                self.breakpoints.remove(pc)
                print(f"Breakpoint cleared at PC {pc}")
            else:
                print(f"No breakpoint at PC {pc}")
        except ValueError:
            print("Invalid PC value")
    
    def do_list(self, arg):
        """List source code around current position. Alias: l"""
        if not self.current_trace or not self.source_lines:
            print("No source available.")
            return
        
        step = self.current_trace.steps[self.current_step]
        source_info = self.source_map.get(step.pc)
        
        if source_info:
            _, line_num = source_info
            
            # Find the source file that contains this line number
            source_lines = None
            source_file = None
            for file_path, lines in self.source_lines.items():
                if 0 < line_num <= len(lines):
                    source_lines = lines
                    source_file = file_path
                    break
            
            if source_lines:
                # Show 5 lines before and after
                start = max(0, line_num - 5)
                end = min(len(source_lines), line_num + 5)
                
                # Show filename if multiple files
                if len(self.source_lines) > 1:
                    print(f"File: {os.path.basename(source_file)}")
                
                for i in range(start, end):
                    marker = "=>" if i + 1 == line_num else "  "
                    print(f"{marker} {i+1:4d}: {source_lines[i].rstrip()}")
            else:
                print(f"No source file found for line {line_num}")
        else:
            print(f"No source mapping for PC {step.pc}")
    
    def do_l(self, arg):
        """Alias for list"""
        self.do_list(arg)
    
    def do_print(self, arg):
        """Print value from stack/memory/storage or variable. Usage: print <variable_name> or print stack[0]"""
        if not self.current_trace:
            print("No transaction loaded.")
            return
        
        step = self.current_trace.steps[self.current_step]
        
        if not arg:
            print("Usage: print <expression>")
            print("Examples: print amount, print stack[0], print storage[0x0], print memory[0x40:0x60]")
            return
        
        try:
            # First try to resolve as a variable name from ETHDebug
            if self.tracer.ethdebug_info:
                var_result = self._evaluate_variable_watch(step, arg)
                if var_result is not None:
                    var_name = var_result['name']
                    var_value = var_result['value']
                    var_type = var_result['type']
                    location = var_result['location']
                    print(f"{var_name} = {var_value} ({var_type}) @ {location}")
                    return
                    
            # Fall back to function parameters if ETHDebug doesn't have the variable
            if self.current_function and self.current_function.args:
                for param_name, param_value in self.current_function.args:
                    if param_name == arg:
                        print(f"{param_name} = {param_value} (function parameter)")
                        return
            
            # Fall back to stack/memory/storage expressions
            if arg.startswith("stack[") and arg.endswith("]"):
                index = int(arg[6:-1])
                if 0 <= index < len(step.stack):
                    value = step.stack[index]
                    print(f"stack[{index}] = {value}")
                    # Try to interpret the value
                    if value.startswith("0x"):
                        int_val = int(value, 16)
                        if int_val < 10**9:
                            print(f"  = {int_val} (decimal)")
                else:
                    print(f"Stack index {index} out of range (stack size: {len(step.stack)})")
            
            elif arg.startswith("storage[") and arg.endswith("]"):
                key = arg[8:-1]
                if key.startswith("0x"):
                    key = key[2:]
                if step.storage and key in step.storage:
                    value = step.storage[key]
                    print(f"storage[0x{key}] = 0x{value}")
                else:
                    print(f"storage[0x{key}] = 0x0 (not set)")
            
            elif "memory[" in arg:
                # Parse memory range
                import re
                match = re.match(r'memory\[(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)\]', arg)
                if match:
                    start = int(match.group(1), 16)
                    end = int(match.group(2), 16)
                    if step.memory:
                        mem_hex = step.memory[start*2:end*2]
                        print(f"memory[{match.group(1)}:{match.group(2)}] = 0x{mem_hex}")
                else:
                    print("Invalid memory range format. Use: memory[0x40:0x60]")
            
            else:
                print(f"Unknown expression: {arg}")
                print("Try: variable name, stack[index], storage[key], or memory[start:end]")
                
        except Exception as e:
            print(f"Error evaluating expression: {e}")
    
    def do_p(self, arg):
        """Alias for print"""
        self.do_print(arg)
    
    def do_info(self, arg):
        """Show information. Usage: info [registers|stack|memory|storage|gas]"""
        if not self.current_trace:
            print("No transaction loaded.")
            return
        
        step = self.current_trace.steps[self.current_step]
        
        if not arg or arg == "registers":
            print(f"PC: {step.pc}")
            print(f"Operation: {step.op}")
            print(f"Gas: {step.gas} (cost: {step.gas_cost})")
            print(f"Depth: {step.depth}")
        
        if not arg or arg == "stack":
            print(f"\nStack ({len(step.stack)} items):")
            for i, val in enumerate(step.stack[:10]):
                print(f"  [{i}] {val}")
            if len(step.stack) > 10:
                print(f"  ... {len(step.stack) - 10} more items")
        
        if arg == "memory" and step.memory:
            print("\nMemory (first 256 bytes):")
            for i in range(0, min(512, len(step.memory)), 64):
                mem_line = step.memory[i:i+64]
                print(f"  0x{i//2:04x}: {mem_line}")
        
        if arg == "storage" and step.storage:
            print("\nStorage (non-zero values):")
            for key, val in sorted(step.storage.items())[:10]:
                print(f"  [0x{key}] = 0x{val}")
            if len(step.storage) > 10:
                print(f"  ... {len(step.storage) - 10} more entries")
        
        if arg == "gas":
            print(f"\nGas used: {self.current_trace.gas_used}")
            print(f"Current gas: {step.gas}")
            print(f"Last operation cost: {step.gas_cost}")
    
    def do_disasm(self, arg):
        """Disassemble around current PC"""
        if not self.current_trace:
            print("No transaction loaded.")
            return
        
        # This would show disassembly with source mapping
        step = self.current_trace.steps[self.current_step]
        print(f"PC {step.pc}: {step.op}")
        
        # Show next few instructions if available
        for i in range(1, min(5, len(self.current_trace.steps) - self.current_step)):
            next_step = self.current_trace.steps[self.current_step + i]
            print(f"PC {next_step.pc}: {next_step.op}")
    
    def do_where(self, arg):
        """Show current position in call stack. Aliases: backtrace, bt"""
        if not self.function_trace:
            print("No function trace available.")
            return
        
        print(f"\n{bold('Call Stack:')}")
        print(dim("-" * 50))
        
        # Find active call stack based on current step
        active_calls = []
        for func in self.function_trace:
            if func.entry_step <= self.current_step <= (func.exit_step or len(self.current_trace.steps)):
                active_calls.append(func)
        
        # Display call stack
        for i, func in enumerate(active_calls):
            marker = "=>" if func == self.current_function else "  "
            indent = "  " * func.depth
            
            # Format function info
            func_info = f"{func.name}"
            if func.call_type:
                func_info += f" {dim(f'[{func.call_type}]')}"
            
            # Format location
            location = ""
            if func.source_line:
                if self.tracer.ethdebug_info:
                    location = f" at {info(f'line {func.source_line}')}"
                else:
                    location = f" at {info(f'line {func.source_line}')}"
            
            print(f"{marker} {indent}#{i} {cyan(func_info)}{location}")
            
            # Show parameters for current function
            if func == self.current_function and func.args:
                for param_name, param_value in func.args:
                    print(f"     {indent}{info(param_name)}: {cyan(str(param_value))}")
        
        print(dim("-" * 50))
    
    def do_backtrace(self, arg):
        """Alias for where"""
        self.do_where(arg)
    
    def do_bt(self, arg):
        """Alias for where"""
        self.do_where(arg)
    
    def do_watch(self, arg):
        """Add variable watch. Usage: watch <variable_name> or watch <expression>"""
        if not arg:
            # List watches
            if self.watch_expressions:
                print("Watch expressions:")
                for i, expr in enumerate(self.watch_expressions):
                    print(f"  {i}: {expr}")
            else:
                print("No watch expressions.")
            return
        
        # Support special commands
        if arg.startswith('remove ') or arg.startswith('delete '):
            try:
                index = int(arg.split()[1])
                if 0 <= index < len(self.watch_expressions):
                    removed = self.watch_expressions.pop(index)
                    print(f"Removed watch: {removed}")
                else:
                    print(f"Invalid watch index: {index}")
            except (ValueError, IndexError):
                print("Usage: watch remove <index>")
            return
        elif arg == 'clear':
            self.watch_expressions.clear()
            print("All watch expressions cleared.")
            return
        
        self.watch_expressions.append(arg)
        print(f"Watch expression added: {arg}")
    
    def do_history(self, arg):
        """Show variable history. Usage: history [variable_name]"""
        if not self.variable_history:
            print("No variable history available.")
            return
        
        if not arg:
            # Show all variables with history
            print("Variables with history:")
            for var_name, history in self.variable_history.items():
                print(f"  {info(var_name)}: {len(history)} changes")
            print(f"\nUse {info('history <variable_name>')} to see details")
            return
        
        var_name = arg.strip()
        if var_name not in self.variable_history:
            print(f"No history found for variable '{var_name}'")
            return
        
        history = self.variable_history[var_name]
        print(f"\n{bold(f'History for variable: {var_name}')}")
        print(dim("-" * 60))
        
        for step, value, var_type, location in history:
            # Format value for display
            if isinstance(value, int) and value > 1000000:
                value_str = f"{value} (0x{value:x})"
            else:
                value_str = str(value)
            
            print(f"Step {highlight(f'{step:4d}')}: {cyan(value_str)} ({dim(var_type)}) @ {dim(location)}")
        
        print(dim("-" * 60))
        print(f"Total changes: {len(history)}")
    
    def do_vars(self, arg):
        """Show all variables at current step. Usage: vars"""
        if not self.current_trace:
            print("No transaction loaded.")
            return
        
        step = self.current_trace.steps[self.current_step]
        
        if not self.tracer.ethdebug_info:
            print("No ETHDebug information available.")
            return
        
        variables = self.tracer.ethdebug_info.get_variables_at_pc(step.pc)
        
        # If no ETHDebug variables, fall back to function parameters
        if not variables:
            if self.current_function and self.current_function.args:
                print(f"{cyan('Function Parameters:')}")
                for param_name, param_value in self.current_function.args:
                    print(f"  {info(param_name)}: {cyan(str(param_value))} (function parameter)")
            else:
                print("No variables or parameters available at current step.")
            return
        
        print(f"\n{bold('All Variables at Current Step:')}")
        print(dim("-" * 50))
        
        # Separate parameters and locals
        param_names = set()
        if self.current_function and self.current_function.args:
            param_names = {param[0] for param in self.current_function.args}
        
        params = []
        locals_vars = []
        
        for var in variables:
            if var.name in param_names:
                params.append(var)
            else:
                locals_vars.append(var)
        
        # Show parameters
        if params:
            print(f"\n{cyan('Parameters:')}")
            for var in params:
                self._print_variable_info(var, step)
        
        # Show local variables
        if locals_vars:
            print(f"\n{cyan('Local Variables:')}")
            for var in locals_vars:
                self._print_variable_info(var, step)
        
        print(dim("-" * 50))
    
    def _print_variable_info(self, var, step):
        """Helper to print variable information."""
        try:
            value = None
            location_str = f"{var.location_type}[{var.offset}]"
            
            if var.location_type == "stack" and var.offset < len(step.stack):
                raw_value = step.stack[var.offset]
                value = self.tracer.decode_value(raw_value, var.type)
            elif var.location_type == "memory" and step.memory:
                value = self.tracer.extract_from_memory(step.memory, var.offset, var.type)
            elif var.location_type == "storage" and step.storage:
                value = self.tracer.extract_from_storage(step.storage, var.offset, var.type)
            
            if value is not None:
                if isinstance(value, int) and value > 1000000:
                    value_str = f"{value} (0x{value:x})"
                else:
                    value_str = str(value)
                print(f"  {info(var.name)}: {cyan(value_str)} ({dim(var.type)}) @ {dim(location_str)}")
            else:
                print(f"  {info(var.name)}: {warning('?')} ({dim(var.type)}) @ {dim(location_str)}")
        except Exception as e:
            print(f"  {info(var.name)}: {error('error')} ({dim(var.type)}) @ {dim(location_str)}")
    
    def do_filter(self, arg):
        """Configure variable display filters. Usage: filter <command> [args]"""
        if not arg:
            # Show current filter settings
            print(f"\n{bold('Variable Display Filters:')}")
            print(dim("-" * 40))
            
            filters = self.variable_filters
            print(f"Hide parameters: {info(str(filters['hide_parameters']))}")
            print(f"Hide temporaries: {info(str(filters['hide_temporaries']))}")
            
            if filters['show_types']:
                print(f"Show only types: {info(', '.join(filters['show_types']))}")
            if filters['hide_types']:
                print(f"Hide types: {info(', '.join(filters['hide_types']))}")
            
            if filters['show_locations']:
                print(f"Show only locations: {info(', '.join(filters['show_locations']))}")
            if filters['hide_locations']:
                print(f"Hide locations: {info(', '.join(filters['hide_locations']))}")
            
            if filters['name_pattern']:
                print(f"Name pattern: {info(filters['name_pattern'])}")
            
            print(dim("-" * 40))
            print(f"\nUsage: {info('filter <command> [args]')}")
            print(f"Commands: show-params, hide-params, show-temps, hide-temps")
            print(f"          show-type <type>, hide-type <type>, show-location <loc>, hide-location <loc>")
            print(f"          name-pattern <regex>, clear-filters")
            return
        
        parts = arg.split()
        command = parts[0]
        
        if command == 'show-params':
            self.variable_filters['hide_parameters'] = False
            print("Now showing function parameters")
        elif command == 'hide-params':
            self.variable_filters['hide_parameters'] = True
            print("Now hiding function parameters")
        elif command == 'show-temps':
            self.variable_filters['hide_temporaries'] = False
            print("Now showing temporary variables")
        elif command == 'hide-temps':
            self.variable_filters['hide_temporaries'] = True
            print("Now hiding temporary variables")
        elif command == 'show-type' and len(parts) > 1:
            var_type = parts[1]
            self.variable_filters['show_types'].add(var_type)
            self.variable_filters['hide_types'].discard(var_type)
            print(f"Now showing only variables of type: {var_type}")
        elif command == 'hide-type' and len(parts) > 1:
            var_type = parts[1]
            self.variable_filters['hide_types'].add(var_type)
            self.variable_filters['show_types'].discard(var_type)
            print(f"Now hiding variables of type: {var_type}")
        elif command == 'show-location' and len(parts) > 1:
            location = parts[1]
            self.variable_filters['show_locations'].add(location)
            self.variable_filters['hide_locations'].discard(location)
            print(f"Now showing only variables in location: {location}")
        elif command == 'hide-location' and len(parts) > 1:
            location = parts[1]
            self.variable_filters['hide_locations'].add(location)
            self.variable_filters['show_locations'].discard(location)
            print(f"Now hiding variables in location: {location}")
        elif command == 'name-pattern' and len(parts) > 1:
            pattern = ' '.join(parts[1:])
            try:
                import re
                re.compile(pattern)  # Test if valid regex
                self.variable_filters['name_pattern'] = pattern
                print(f"Set name pattern filter: {pattern}")
            except re.error as e:
                print(f"Invalid regex pattern: {e}")
        elif command == 'clear-filters':
            self.variable_filters = {
                'show_types': set(),
                'hide_types': set(),
                'show_locations': set(),
                'hide_locations': set(),
                'name_pattern': None,
                'hide_parameters': False,
                'hide_temporaries': True,
            }
            print("All filters cleared")
        else:
            print(f"Unknown filter command: {command}")
            print("Use 'filter' without arguments to see usage help")
    
    def do_debug_ethdebug(self, arg):
        """Debug ETHDebug data. Usage: debug_ethdebug [pc]"""
        if not self.tracer.ethdebug_info:
            print("No ETHDebug information available.")
            return
        
        if arg:
            # Check specific PC
            try:
                pc = int(arg, 0)  # Support hex with 0x prefix
            except ValueError:
                print("Invalid PC value")
                return
        else:
            # Use current PC
            if not self.current_trace:
                print("No transaction loaded.")
                return
            pc = self.current_trace.steps[self.current_step].pc
        
        print(f"\n{bold(f'ETHDebug Information for PC {pc}:')}")
        print(dim("-" * 50))
        
        # Check if we have an instruction at this PC
        instruction = self.tracer.ethdebug_info.get_instruction_at_pc(pc)
        if instruction:
            print(f"Instruction: {instruction.mnemonic}")
            if instruction.arguments:
                print(f"Arguments: {', '.join(instruction.arguments)}")
            
            # Check source mapping
            source_info = self.tracer.ethdebug_info.get_source_info(pc)
            if source_info:
                source_path, offset, length = source_info
                line, col = self.tracer.ethdebug_parser.offset_to_line_col(source_path, offset)
                print(f"Source: {source_path}:{line}:{col}")
            else:
                print("No source mapping")
        else:
            print("No instruction found at this PC")
        
        # Check variable information
        variables = self.tracer.ethdebug_info.get_variables_at_pc(pc)
        print(f"\nVariables: {len(variables)} found")
        for var in variables:
            print(f"  - {var.name}: {var.type} @ {var.location_type}[{var.offset}] (range: {var.pc_range})")
        
        # Check if we have variable information for nearby PCs
        print(f"\nVariable info for nearby PCs:")
        for check_pc in range(max(0, pc - 10), pc + 11):
            nearby_vars = self.tracer.ethdebug_info.get_variables_at_pc(check_pc)
            if nearby_vars:
                print(f"  PC {check_pc}: {len(nearby_vars)} variables")
        
        print(dim("-" * 50))
    
    def do_exit(self, arg):
        """Exit the debugger"""
        print("Goodbye!")
        return True
    
    def do_mode(self, arg):
        """Switch display mode. Usage: mode [source|asm]"""
        if not arg:
            print(f"Current mode: {info(self.display_mode)}")
            return
        
        if arg.lower() in ['source', 'src']:
            self.display_mode = 'source'
            print(f"Switched to {success('source')} mode")
        elif arg.lower() in ['asm', 'assembly']:
            self.display_mode = 'asm'
            print(f"Switched to {success('assembly')} mode")
        else:
            print(f"Invalid mode. Use 'source' or 'asm'")
        
        # Redisplay current state in new mode
        if self.current_trace:
            self._show_current_state()
    
    def do_quit(self, arg):
        """Alias for exit"""
        return self.do_exit(arg)
    
    def do_q(self, arg):
        """Alias for exit"""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl-D"""
        print()
        return self.do_exit(arg)
    
    def _get_source_line_for_step(self, step_index: int) -> Optional[int]:
        """Get source line number for a given step."""
        if step_index >= len(self.current_trace.steps):
            return None
            
        step = self.current_trace.steps[step_index]
        
        if self.tracer.ethdebug_info:
            # Use ETHDebug info
            context = self.tracer.ethdebug_parser.get_source_context(step.pc, context_lines=0)
            if context:
                return context['line']
        elif self.source_map:
            # Use basic source map
            source_info = self.source_map.get(step.pc)
            if source_info:
                return source_info[1]
        
        return None
    
    def _update_current_function(self):
        """Update current function based on current step."""
        if not self.function_trace:
            return
            
        # Find which function we're in
        for func in self.function_trace:
            if func.entry_step <= self.current_step <= (func.exit_step or len(self.current_trace.steps)):
                self.current_function = func
                break
    
    def _track_variable_changes(self):
        """Track changes in variable values for history."""
        if not self.tracer.ethdebug_info or self.current_step >= len(self.current_trace.steps):
            return
        
        step = self.current_trace.steps[self.current_step]
        variables = self.tracer.ethdebug_info.get_variables_at_pc(step.pc)
        
        for var in variables:
            try:
                # Extract the current value
                value = None
                location_str = f"{var.location_type}[{var.offset}]"
                
                if var.location_type == "stack" and var.offset < len(step.stack):
                    raw_value = step.stack[var.offset]
                    value = self.tracer.decode_value(raw_value, var.type)
                elif var.location_type == "memory" and step.memory:
                    value = self.tracer.extract_from_memory(step.memory, var.offset, var.type)
                elif var.location_type == "storage" and step.storage:
                    value = self.tracer.extract_from_storage(step.storage, var.offset, var.type)
                
                # Initialize history for this variable if needed
                if var.name not in self.variable_history:
                    self.variable_history[var.name] = []
                
                # Check if value has changed from last recorded value
                history = self.variable_history[var.name]
                if not history or history[-1][1] != value:
                    # Record the change
                    history.append((self.current_step, value, var.type, location_str))
                    
                    # Limit history size to prevent memory issues
                    if len(history) > 1000:
                        history.pop(0)
                        
            except Exception:
                # Ignore errors in tracking
                pass
    
    def _show_current_state(self):
        """Display current execution state (source-oriented)."""
        if not self.current_trace or self.current_step >= len(self.current_trace.steps):
            return
        
        step = self.current_trace.steps[self.current_step]
        
        # Get source information
        source_file = None
        source_line_num = None
        source_content = None
        
        if self.tracer.ethdebug_info:
            context = self.tracer.ethdebug_parser.get_source_context(step.pc, context_lines=2)
            if context:
                source_file = os.path.basename(context['file'])
                source_line_num = context['line']
                source_content = context['content']
        elif self.source_map:
            source_info = self.source_map.get(step.pc)
            if source_info and self.source_lines:
                _, source_line_num = source_info
                # Find the source file
                for file_path, lines in self.source_lines.items():
                    if 0 < source_line_num <= len(lines):
                        source_file = os.path.basename(file_path)
                        source_content = lines[source_line_num - 1].strip()
                        break
        
        # Display based on mode
        if self.display_mode == "source" and source_file:
            # Source-level display
            print(f"\n{info(f'{source_file}:{source_line_num}')}", end="")
            if self.current_function:
                print(f" in {function_name(self.current_function.name)}", end="")
            print()
            
            # Show source context
            if source_content:
                print(f"{dim('=>')} {source_line(source_content)}")
            
            # Show parameters if at function entry
            if self.current_function and self.current_step == self.current_function.entry_step:
                if self.current_function.args:
                    print(f"{dim('Parameters:')}")
                    for param_name, param_value in self.current_function.args:
                        print(f"  {info(param_name)}: {cyan(str(param_value))}")
            
            # Show local variables if ETHDebug is available
            self._show_local_variables(step)
            
            # Minimal instruction info
            print(f"{dim('[')} {dim('Step')} {highlight(f'{self.current_step}')} | "
                  f"{dim('Gas:')} {gas_value(step.gas)} | "
                  f"{dim('PC:')} {pc_value(step.pc)} | "
                  f"{opcode(step.op)} {dim(']')}")
        else:
            # Assembly-level display (fallback or when in asm mode)
            print(f"\n{dim('Step')} {highlight(f'{self.current_step}/{len(self.current_trace.steps)-1}')}")
            
            # Function context
            func_name = ""
            if self.current_function:
                func_name = f" in {function_name(self.current_function.name)}"
            
            # Format the main execution line
            pc_str = pc_value(step.pc)
            op_str = opcode(f"{step.op:<16}")
            gas_str = gas_value(step.gas)
            stack_str = self._format_stack_colored(step)
            
            print(f"PC: {pc_str} | {op_str} | Gas: {gas_str} | {stack_str}{func_name}")
            
            # Show source if available
            if source_file and source_content:
                print(f"{dim('Source:')} {info(f'{source_file}:{source_line_num}')}")
                print(f"  {dim('=>')} {source_line(source_content)}")
            
            # Show local variables in assembly mode too
            self._show_local_variables(step)
        
        # Watch expressions
        if self.watch_expressions:
            self._evaluate_watch_expressions(step)
    
    def _show_local_variables(self, step):
        """Display local variables at the current step."""
        if not self.tracer.ethdebug_info:
            return
        
        # Get variables at current PC
        variables = self.tracer.ethdebug_info.get_variables_at_pc(step.pc)
        if not variables:
            return
        
        # Apply filters to variables
        filtered_vars = []
        param_names = set()
        if self.current_function and self.current_function.args:
            param_names = {param[0] for param in self.current_function.args}
        
        for var in variables:
            # Apply filtering logic
            if not self._should_show_variable(var, param_names):
                continue
            filtered_vars.append(var)
        
        if not filtered_vars:
            return
        
        print(f"{dim('Local Variables:')}")
        for var in filtered_vars:
            try:
                # Extract the variable value based on its location
                value = None
                location_str = f"{var.location_type}[{var.offset}]"
                
                if var.location_type == "stack" and var.offset < len(step.stack):
                    raw_value = step.stack[var.offset]
                    value = self.tracer.decode_value(raw_value, var.type)
                elif var.location_type == "memory" and step.memory:
                    value = self.tracer.extract_from_memory(step.memory, var.offset, var.type)
                elif var.location_type == "storage" and step.storage:
                    value = self.tracer.extract_from_storage(step.storage, var.offset, var.type)
                
                # Format the value for display
                if value is not None:
                    if isinstance(value, int) and value > 1000000:
                        # Show large numbers in hex too
                        value_str = f"{value} (0x{value:x})"
                    else:
                        value_str = str(value)
                    print(f"  {info(var.name)}: {cyan(value_str)} ({dim(var.type)}) @ {dim(location_str)}")
                else:
                    print(f"  {info(var.name)}: {warning('?')} ({dim(var.type)}) @ {dim(location_str)}")
                    
            except Exception as e:
                print(f"  {info(var.name)}: {error('error')} ({dim(var.type)}) @ {dim(location_str)}")
    
    def _should_show_variable(self, var, param_names):
        """Check if a variable should be displayed based on current filters."""
        import re
        
        # Check if it's a parameter and we're hiding parameters
        if self.variable_filters['hide_parameters'] and var.name in param_names:
            return False
        
        # Check if it's a temporary variable and we're hiding them
        if self.variable_filters['hide_temporaries']:
            # Common patterns for temporary variables
            if (var.name.startswith('_') or 
                var.name.startswith('tmp') or 
                var.name.startswith('temp') or
                var.name.isdigit() or
                var.name in ['$', '$$']):
                return False
        
        # Check type filters
        if self.variable_filters['show_types']:
            # If show_types is specified, only show those types
            if var.type not in self.variable_filters['show_types']:
                return False
        
        if var.type in self.variable_filters['hide_types']:
            return False
        
        # Check location filters
        if self.variable_filters['show_locations']:
            # If show_locations is specified, only show those locations
            if var.location_type not in self.variable_filters['show_locations']:
                return False
        
        if var.location_type in self.variable_filters['hide_locations']:
            return False
        
        # Check name pattern
        if self.variable_filters['name_pattern']:
            try:
                if not re.match(self.variable_filters['name_pattern'], var.name):
                    return False
            except re.error:
                # Invalid regex, ignore pattern filter
                pass
        
        return True
    
    def _evaluate_watch_expressions(self, step):
        """Evaluate and display watch expressions."""
        print(f"{dim('Watch Expressions:')}")
        
        for i, expr in enumerate(self.watch_expressions):
            try:
                # Check if it's a variable name first
                value = self._evaluate_variable_watch(step, expr)
                
                if value is not None:
                    # Successfully found as a variable
                    if isinstance(value, dict):
                        var_name = value['name']
                        var_value = value['value']
                        var_type = value['type']
                        location = value['location']
                        print(f"  [{i}] {info(var_name)}: {cyan(str(var_value))} ({dim(var_type)}) @ {dim(location)}")
                    else:
                        print(f"  [{i}] {info(expr)}: {cyan(str(value))}")
                else:
                    # Fall back to expression evaluation (stack/memory/storage)
                    self._print_watch_expression(i, expr, step)
                    
            except Exception as e:
                print(f"  [{i}] {info(expr)}: {error(f'Error: {e}')}")
    
    def _evaluate_variable_watch(self, step, var_name):
        """Try to evaluate a watch expression as a variable name."""
        if not self.tracer.ethdebug_info:
            return None
            
        # Get all variables at current PC
        variables = self.tracer.ethdebug_info.get_variables_at_pc(step.pc)
        
        for var in variables:
            if var.name == var_name:
                try:
                    value = None
                    location_str = f"{var.location_type}[{var.offset}]"
                    
                    if var.location_type == "stack" and var.offset < len(step.stack):
                        raw_value = step.stack[var.offset]
                        value = self.tracer.decode_value(raw_value, var.type)
                    elif var.location_type == "memory" and step.memory:
                        value = self.tracer.extract_from_memory(step.memory, var.offset, var.type)
                    elif var.location_type == "storage" and step.storage:
                        value = self.tracer.extract_from_storage(step.storage, var.offset, var.type)
                    
                    return {
                        'name': var.name,
                        'value': value,
                        'type': var.type,
                        'location': location_str
                    }
                except Exception:
                    pass
        
        return None
    
    def _print_watch_expression(self, index, expr, step):
        """Print a watch expression that's not a simple variable name."""
        # This handles the existing stack[]/memory[]/storage[] syntax
        if expr.startswith("stack[") and expr.endswith("]"):
            try:
                stack_index = int(expr[6:-1])
                if 0 <= stack_index < len(step.stack):
                    value = step.stack[stack_index]
                    print(f"  [{index}] {info(expr)}: {cyan(value)}")
                else:
                    print(f"  [{index}] {info(expr)}: {warning('out of range')}")
            except ValueError:
                print(f"  [{index}] {info(expr)}: {error('invalid index')}")
        elif expr.startswith("storage[") and expr.endswith("]"):
            try:
                key = expr[8:-1]
                if key.startswith("0x"):
                    key = key[2:]
                if step.storage and key in step.storage:
                    value = step.storage[key]
                    print(f"  [{index}] {info(expr)}: {cyan(f'0x{value}')}")
                else:
                    print(f"  [{index}] {info(expr)}: {cyan('0x0')} {dim('(not set)')}")
            except Exception:
                print(f"  [{index}] {info(expr)}: {error('invalid storage key')}")
        else:
            # Try to evaluate as a general expression
            try:
                # This could be extended to support more complex expressions
                print(f"  [{index}] {info(expr)}: {warning('unsupported expression')}")
            except Exception as e:
                print(f"  [{index}] {info(expr)}: {error(str(e))}")
    
    def _format_stack_colored(self, step) -> str:
        """Format stack with colors."""
        if not step.stack:
            return dim("[empty]")
        
        items = []
        max_items = 3
        
        for i, val in enumerate(step.stack[:max_items]):
            items.append(stack_item(i, val))
        
        if len(step.stack) > max_items:
            items.append(dim(f"... +{len(step.stack) - max_items} more"))
        
        return " ".join(items)
    
    def emptyline(self):
        """Handle empty line (don't repeat last command)"""
        pass
    
    def default(self, line):
        """Handle unknown commands."""
        print(f"{error('Unknown command:')} '{line}'")
        print(f"Type {info('help')} to see available commands.")
    
    def do_snapshot(self, _):
        """Create an EVM snapshot (returns id)."""
        if not getattr(self, "tracer", None) or not hasattr(self.tracer, "snapshot_state"):
            print("Snapshot not available.")
            return
        sid = self.tracer.snapshot_state()
        print(f"Snapshot: {sid}" if sid else "Snapshot failed.")

    def do_revert(self, arg):
        """Revert to a snapshot. Usage: revert [snapshot_id] (omit to revert to baseline)"""
        if not getattr(self, "tracer", None) or not hasattr(self.tracer, "revert_state"):
            print("Revert not available.")
            return
        target = arg.strip() or None
        ok = self.tracer.revert_state(target)
        print("Reverted." if ok else "Revert failed.")
    
    def do_help(self, arg):
        """Show help information."""
        if arg:
            # Show help for specific command
            cmd.Cmd.do_help(self, arg)
        else:
            # Show formatted help menu
            print(f"\n{bold('SolDB EVM Debugger Commands')}")
            print(dim("=" * 60))
            
            # Execution Control
            print(f"\n{cyan('Execution Control:')}")
            print(f"  {info('run')} <tx_hash>     - Load and debug a transaction")
            print(f"  {info('next')} (n/step/s)   - Step to next source line")
            print(f"  {info('nexti')} (ni/stepi)  - Step to next instruction")  
            print(f"  {info('continue')} (c)      - Continue execution")
            
            # Breakpoints
            print(f"\n{cyan('Breakpoints:')}")
            print(f"  {info('break')} <pc>        - Set breakpoint at PC")
            print(f"  {info('break')} <file>:<ln> - Set breakpoint at source line")
            print(f"  {info('clear')} <pc>        - Clear breakpoint")
            
            # Information Display
            print(f"\n{cyan('Information Display:')}")
            print(f"  {info('list')} (l)          - Show source code")
            print(f"  {info('print')} (p) <expr>  - Print variable or expression")
            print(f"  {info('vars')}              - Show all variables at current step")
            print(f"  {info('info')} <what>       - Show info (registers/stack/memory/storage/gas)")
            print(f"  {info('where')} (bt)        - Show call stack")
            print(f"  {info('disasm')}            - Show disassembly")
            
            # Display Settings
            print(f"\n{cyan('Display Settings:')}")
            print(f"  {info('mode')} <source|asm> - Switch display mode")
            print(f"  {info('watch')} <expr>      - Add/manage watch expressions")
            print(f"  {info('filter')} <cmd>      - Configure variable display filters")
            
            # Variable Analysis
            print(f"\n{cyan('Variable Analysis:')}")
            print(f"  {info('history')} [var]     - Show variable change history")
            
            # Debug Commands
            print(f"\n{cyan('Debug Commands:')}")
            print(f"  {info('debug_ethdebug')}    - Debug ETHDebug data at current PC")
            
            # Other
            print(f"\n{cyan('Other Commands:')}")
            print(f"  {info('help')} [command]    - Show help")
            print(f"  {info('exit')} (quit/q)    - Exit debugger")
            
            print(f"\n{dim('Use')} {info('help <command>')} {dim('for detailed help on a specific command.')}")
            print(dim("=" * 60) + "\n")

    def cmdloop(self, intro=None):
        """Override cmdloop to show current state after intro but before first prompt."""
        if self.init:
            # Call parent cmdloop with intro
            if intro is not None:
                self.intro = intro
            # Print intro if it exists
            if self.intro:    
                self.stdout.write(str(self.intro)+"\n")
            # Show current state after intro but before first prompt
            if self.current_trace:
                self._show_current_state()
            # Start the command loop without intro (already printed)
            super().cmdloop(intro="")
        else:
            super().cmdloop(intro=self.intro)

def main():
    """Main entry point for the EVM REPL debugger."""
    import argparse
    
    parser = argparse.ArgumentParser(description='EVM REPL Debugger')
    parser.add_argument('--contract', '-c', help='Contract address')
    parser.add_argument('--debug', '-d', help='Debug info file (.zasm)')
    parser.add_argument('--rpc', '-r', default='http://localhost:8545', help='RPC URL')
    parser.add_argument('--tx', '-t', help='Transaction hash to debug immediately')
    
    args = parser.parse_args()
    
    # Create debugger
    debugger = EVMDebugger(
        contract_address=args.contract,
        debug_file=args.debug,
        rpc_url=args.rpc
    )
    
    # Auto-load transaction if provided
    if args.tx:
        debugger.do_run(args.tx)
    
    # Start REPL
    try:
        debugger.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 0


if __name__ == '__main__':
    main()
