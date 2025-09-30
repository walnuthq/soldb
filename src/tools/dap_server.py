#!/usr/bin/env python3
import json
import sys
import os

import io
from typing import Dict, Any, List, Optional
from zipfile import Path
from pathlib import Path

from soldb.evm_repl import EVMDebugger
from soldb.transaction_tracer import TransactionTracer
from soldb.ethdebug_dir_parser import ETHDebugDirParser
from soldb.ethdebug_parser import ETHDebugInfo
from soldb.multi_contract_ethdebug_parser import MultiContractETHDebugParser
from eth_utils.address import is_address

CRLF = b"\r\n"

class CaptureOutput:
    """Context manager to capture stdout from debugger."""
    def __init__(self, dap_server):
        self.dap_server = dap_server
        self.original_stdout = None
        self.captured_output = io.StringIO()
        
    def __enter__(self):
        self.original_stdout = sys.stdout
        sys.stdout = self.captured_output
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original stdout
        sys.stdout = self.original_stdout
        
        # Send captured output to VS Code
        output = self.captured_output.getvalue()
        if output:
            self.dap_server._send_output(output)
        
        self.captured_output.close()

class WalnutDAPServer:
    """Debug Adapter Protocol server for walnut-cli (stdio version)"""
    def __init__(self):
        self._seq = 1
        self.debugger: Optional[EVMDebugger] = None
        self.breakpoints: Dict[str, List[int]] = {}
        self.thread_id = 1
        self.log_sock = None

    def _capture_output(self):
        """Context manager to capture stdout and send as DAP output events."""
        return CaptureOutput(self)

    def _send_output(self, text: str):
        """Send output to VS Code via DAP output event."""
        self._event("output", {
            "output": text,
            "category": "stdout"
        })

    # ---- DAP transport helpers ----
    def _send(self, msg: Dict[str, Any]):
        body = json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(body)}".encode("utf-8") + CRLF + CRLF
        sys.stdout.buffer.write(header + body)
        sys.stdout.buffer.flush()

    def _event(self, event: str, body: Optional[Dict[str, Any]] = None):
        evt = {
            "type": "event",
            "seq": self._seq,
            "event": event,
            "body": body or {}
        }
        self._seq += 1
        self._send(evt)

    def _response(self, request: Dict[str, Any], success: bool = True, body: Optional[Dict[str, Any]] = None, message: Optional[str] = None):
        resp = {
            "type": "response",
            "seq": self._seq,
            "request_seq": request.get("seq"),
            "success": success,
            "command": request.get("command"),
        }
        if body is not None:
            resp["body"] = body
        if message and not success:
            resp["message"] = message
        self._seq += 1
        self._send(resp)

    def _read(self) -> Optional[Dict[str, Any]]:
        # Parse DAP headers from stdin
        content_length = None
        while True:
            line = sys.stdin.buffer.readline()
            if not line or line == b"\r\n":
                break
            k, _, v = line.partition(b":")
            if k.lower() == b"content-length":
                content_length = int(v.strip())
        if content_length is None:
            return None
        body = sys.stdin.buffer.read(content_length)
        return json.loads(body.decode("utf-8"))

    # ---- DAP request handlers ----
    def initialize(self, request):
        caps = {
            "supportsConfigurationDoneRequest": True,
            "supportsSetBreakpointsRequest": True,
            "supportsTerminateRequest": True,
            "supportsConditionalBreakpoints": True,
            "supportsRestartRequest": True,
        }
        self._response(request, True, {"capabilities": caps})
        self._event("initialized")

    def launch(self, request):
        try:
            args = request.get("arguments", {}) or {}
            
            # Get source file and workspace root
            source = args.get("source")
            workspace_root = args.get("workspaceRoot")
            
            # workspace detection
            if not workspace_root:
                if source:
                    workspace_root = os.path.dirname(source)
                else:
                    workspace_root = os.getcwd()
            
            # Change to workspace root
            os.chdir(workspace_root)
            
            # Enhanced path resolution with fallbacks
            def resolve_path(path_arg):
                if not path_arg:
                    return path_arg
                if os.path.isabs(path_arg):
                    return path_arg
                
                # Try workspace-relative first
                workspace_path = os.path.join(workspace_root, path_arg)
                if os.path.exists(workspace_path):
                    return workspace_path
                
                # Try current directory
                if os.path.exists(path_arg):
                    return os.path.abspath(path_arg)
                
                # Fallback to workspace-relative
                return workspace_path
            
            # Resolve all paths
            contracts = resolve_path(args.get("contracts"))
            ethdebug_dir = resolve_path(args.get("ethdebugDir"))
            rpc_url = args.get("rpc", "http://localhost:8545")
            block = args.get("block", None)
            from_addr = args.get("from_addr", "")
            function_signature = args.get("function", None)
            function_args = args.get("functionArgs", [])
            
            # Store paths for later use in source requests
            self.source_file = source
            self.workspace_root = workspace_root
            contract_name = None
            abi_path = None
            
            if contracts:
                with open(contracts, "r") as f:
                    contracts_data = json.load(f)

                for contract in contracts_data.get('contracts', []):
                    name = contract['name']
                    if name == str(source).split('/')[-1].split('.sol')[0]:
                        contract_address = contract['address']
                        break

            # Create tracer
            try:
                tracer = TransactionTracer(rpc_url)
            except Exception as e:
                raise ValueError(f'Failed to create TransactionTracer: {e}')
            source_map = {}

            if contract_address:
                if not is_address(contract_address):
                    raise ValueError(f'Invalid contract address: {contract_address}')
        
            # Multi-contract mode detection (same as trace_command)
            multi_contract_mode = False
            ethdebug_dirs = []
            if hasattr(args, 'ethdebug_dir') and ethdebug_dir:
                if isinstance(ethdebug_dir, list):
                    ethdebug_dirs = ethdebug_dir
                else:
                    ethdebug_dirs = [ethdebug_dir]
            if getattr(args, 'multi_contract', False) or (ethdebug_dirs and len(ethdebug_dirs) > 1) or contracts:
                multi_contract_mode = True

            if multi_contract_mode:
                multi_parser = MultiContractETHDebugParser()
                # Load from contracts mapping file if provided
                if contracts:
                    try:
                        multi_parser.load_from_mapping_file(contracts)
                    except Exception as e:
                        self._send_output(f"Error loading contracts mapping file: {e}")
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
                                        self._send_output(f"Error loading deployment.json from {spec.path}: {e}\n")
                                        sys.exit(1)
                                else:
                                    self._send_output(f"Warning: No deployment.json found in {spec.path}, skipping...\n")
                    except ValueError as e:
                        sys.exit(1)
                tracer.multi_contract_parser = multi_parser

                # Set primary contract context for simulation (entrypoint contract)
                primary_contract = multi_parser.get_contract_at_address(contract_address)
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
                        self._send_output(f"Warning: No ETHDebug information for entrypoint contract {contract_address}\n")
                    
                    # Try to load ABI for entrypoint contract from common locations
                    if contract_address:
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
                        self._send_output("No valid ethdebug directory specified\n")
                        sys.exit(1)
                    spec = specs[0]
                    address, name, ethdebug_dir = spec.address, spec.name, spec.path
                except ValueError as e:
                    self._send_output(f"Error: {e}")
                    sys.exit(1)
                
                # Check if the contract address matches the ETHDebug address
                if contract_address and contract_address.lower() != address.lower():
                    # Address doesn't match - simulate without source mapping for entrypoint
                    # This is similar to how trace command works
                    source_map = {}
                    if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
                        self._send_output(f"Warning: Contract address {contract_address} does not match ETHDebug address {address}\n")
                        
                    
                    # Try to load ABI for entrypoint contract from common locations
                    if contract_address and ethdebug_dir:
                        # Try to find ABI in current directory
                        for abi_file in Path(ethdebug_dir).glob("*.abi"):
                            tracer.load_abi(str(abi_file))
                            break
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
                # TODO: Implement ABI loading from common locations
                pass

            if getattr(tracer, 'multi_contract_parser', None):
                # In multi-contract mode, find the ethdebug_dir for the entrypoint contract
                entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(contract_address)
                if entrypoint_contract:
                    ethdebug_dir = str(entrypoint_contract.debug_dir)
                    contract_name = entrypoint_contract.name
                else:
                    # Fallback to first ethdebug_dir if entrypoint not found - parse format
                    ethdebug_spec = ethdebug_dir[0] if isinstance(ethdebug_dir, list) else ethdebug_dir
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
                ethdebug_spec = ethdebug_dir[0] if isinstance(ethdebug_dir, list) else ethdebug_dir
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
    
            self._send_output("\nStarting debugger...\n")
            self.debugger = EVMDebugger(
                contract_address=str(contract_address),
                rpc_url=rpc_url,
                ethdebug_dir=ethdebug_dir,
                function_name=function_signature,
                function_args=function_args,
                abi_path=abi_path,
                from_addr=from_addr,
                block=block,
                tracer=tracer,
                contract_name=contract_name
            )

            try:
                # Check prerequisites before simulation
                if not self.debugger.contract_address:
                    raise RuntimeError("No contract address available for simulation")
                
                if not self.debugger.function_name:
                    raise RuntimeError("No function name specified for debugging")
                                
                # Capture stdout from the debugger simulation
                with self._capture_output():
                    self.debugger._do_interactive()
                                    
                if not self.debugger.current_trace:
                    raise RuntimeError("Simulation failed to generate trace - check function name and arguments")              
                
                # Find the actual function entry point (first function call after dispatcher)
                entry_step = 0
                if hasattr(self.debugger, 'function_trace') and len(self.debugger.function_trace) > 0:
                    # Look for the target function by name
                    target_function = None
                    for func in self.debugger.function_trace:
                        if func.name == self.debugger.function_name:
                            target_function = func
                            break
                    
                    if target_function:
                        entry_step = target_function.entry_step
                        self.debugger.current_function = target_function
                    elif len(self.debugger.function_trace) > 1:
                        # Skip dispatcher, go to first actual function
                        entry_step = self.debugger.function_trace[1].entry_step
                        self.debugger.current_function = self.debugger.function_trace[1]
                        self._send_output(f"Using first non-dispatcher function at step {entry_step}\n")
                    else:
                        # Use first function if only one exists
                        entry_step = self.debugger.function_trace[0].entry_step
                        self.debugger.current_function = self.debugger.function_trace[0]
                else:
                    self._send_output("No function trace found, starting at step 0\n")
                    
                # Set debugger to function entry point
                self.debugger.current_step = entry_step

            except Exception as e:
                self._send_output(f"Simulation failed: {e}")
                raise RuntimeError(f"Failed to generate execution trace: {e}")
            
            self._response(request, True, {})
            self._event("thread", {"reason": "started", "threadId": self.thread_id})
            # Stop at function entry point
            self._event("stopped", {"reason": "entry", "threadId": self.thread_id})
        except Exception as e:
            self._send_output(f"Launch failed with error: {e}")
            self._response(request, False, message=str(e))
            return

    def setBreakpoints(self, request):
        args = request.get("arguments", {}) or {}
        breakpoints = args.get("breakpoints", [])
        source_name = args.get("source", {}).get("name", "").split('.')[0]
        lines = []
        functions = []

        # Separate line and function breakpoints
        for bp in breakpoints:
            if "line" in bp:
                lines.append(bp["line"])
            if "functions" in bp:
                functions.extend(bp["functions"])
        self.breakpoints[source_name] = lines[:]
        verified = []
        
        if self.debugger:
            # Register line breakpoints in EVMDebugger
            for line in self.breakpoints[source_name]:
                try:
                    self.debugger.do_break(f"{source_name}:{line}")
                    verified.append({"verified": True, "line": line})
                except Exception:
                    verified.append({"verified": False, "line": line})

            # Register function name breakpoints in EVMDebugger
            for func_name in functions:
                try:
                    self.debugger.do_break(func_name)
                    verified.append({"verified": True, "functions": func_name})
                except Exception:
                    verified.append({"verified": False, "functions": func_name})

        self._response(request, True, {"breakpoints": verified})

    def threads(self, request):
        self._response(request, True, {"threads": [{"id": self.thread_id, "name": "main"}]})

    def continue_(self, request):        
        # Run until end or breakpoint
        if not self.debugger or not self.debugger.current_trace:
            self._response(request, True, {})
            self._event("stopped", {"reason": "breakpoint", "threadId": self.thread_id})
            return
        
        try:
            self.debugger.do_continue("")
        except Exception as e:
            self._send_output(f"Error during continue command: {e}")
            self._response(request, False, message=str(e))
            return
        
        # If continue reaches end of execution
        if self.debugger.current_step >= len(self.debugger.current_trace.steps) - 1:
            self._response(request, True, {"allThreadsContinued": False})
            self._event("exited", {"exitCode": 0})
            return

        self._response(request, True, {"allThreadsContinued": False})
        self._event("stopped", {"reason": "breakpoint", "threadId": self.thread_id})

    def next(self, request):
        # Source-level step
        try:
            if self.debugger:
                self.debugger.do_next("")
                if self.debugger.current_step >= len(self.debugger.current_trace.steps):
                    self._response(request, True, {})
                    self._event("exited", {"exitCode": 0})
                    return
                new_step = self.debugger.current_trace.steps[self.debugger.current_step]
                # If we stepped into a CALL/DELEGATECALL/STATICCALL, step over it
                if new_step.op in ['CALL', 'DELEGATECALL', 'STATICCALL']:
                    self.debugger.do_next("")
                
            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})
        except Exception as e:
            self._response(request, False, message=str(e))

    def stepIn(self, request):
        # Step into function calls
        try:
            if self.debugger:
                while self.debugger.current_step < len(self.debugger.current_trace.steps) - 1:
                    self.debugger.current_step += 1
                    current_op = self.debugger.current_trace.steps[self.debugger.current_step].op
                    # Step in until we hit a CALL/DELEGATECALL/STATICCALL
                    if current_op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                        break
                self.debugger.do_step("")
            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})
        except Exception as e:
            self._response(request, False, message=str(e))

    def stepOut(self, request):
        """Step out of current function - continue until we return to calling code"""
        try:
            if not self.debugger or not self.debugger.current_trace:
                self._response(request, False, message="No debugger or trace available")
                return

            old_step = self.debugger.current_step
            current_depth = None

            # Get current call depth
            if old_step < len(self.debugger.current_trace.steps):
                current_depth = self.debugger.current_trace.steps[old_step].depth

            if current_depth is None:
                return self.next(request)

            # Step until return
            while (self.debugger.current_step < len(self.debugger.current_trace.steps) - 1):

                self.debugger.current_step += 1
                step = self.debugger.current_trace.steps[self.debugger.current_step]

                # Check if we've returned to a higher level
                if step.depth < current_depth:
                    break

                if step.op == "RETURN":
                    # Call the method
                    self.debugger._handle_return_opcode(step)
                    # Check if we've returned to the target depth after handling
                    if self.debugger.current_step < len(self.debugger.current_trace.steps):
                        new_step = self.debugger.current_trace.steps[self.debugger.current_step]
                        if new_step.depth < current_depth:
                            break

                # Handle other exit opcodes
                if step.op in ["REVERT", "STOP"]:
                    if self.debugger.current_step < len(self.debugger.current_trace.steps) - 1:
                        self.debugger.current_step += 1
                        next_step = self.debugger.current_trace.steps[self.debugger.current_step]
                        if next_step.depth < current_depth:
                            break

            # Update current function
            if hasattr(self.debugger, '_update_current_function'):
                self.debugger._update_current_function()

            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})

        except Exception as e:
            self._send_output(f"Error in stepOut: {e}")
            self._response(request, False, message=str(e))

    def stackTrace(self, request):
        try:
            if not self.debugger or not self.debugger.current_trace:
                return self._response(request, True, {"stackFrames": []})

            stack_frames = []
            frame_id = 1
            
            # Build stack frames from function trace 
            current_frame = self._create_stack_frame(
                frame_id, 
                self.debugger.current_step, 
                self.debugger.contract_address,
                is_current=True
            )
            if current_frame:
                stack_frames.append(current_frame)
            
            self._response(request, True, {
                "stackFrames": stack_frames,
                "totalFrames": len(stack_frames)
            })
            
        except Exception as e:
            self._send_output(f"Error in stackTrace: {e}")
            # Return empty stack on error to avoid crashing
            self._response(request, True, {"stackFrames": []})

    def _create_stack_frame(self, frame_id, step_num, contract_address, is_current=False, call_type=None):
        """Create a stack frame for the given step and contract."""
        if not self.debugger or not self.debugger.current_trace or not self.debugger.current_trace.steps:
            return None
            
        if step_num >= len(self.debugger.current_trace.steps):
            return None
            
        step = self.debugger.current_trace.steps[step_num]
        pc = step.pc
        
        # Default frame name
        if is_current and hasattr(self.debugger, "current_function") and self.debugger.current_function:
            func_name = getattr(self.debugger.current_function, "name", None)
            name = func_name or f"pc:{pc}"
        else:
            name = f"{call_type or 'CALL'}@pc:{pc}"
        
        source = None
        line = 1
        col = 1
        
        # Try to resolve source location
        contract_info = None
        if (hasattr(self.debugger, 'tracer') and self.debugger.tracer and 
            hasattr(self.debugger.tracer, 'multi_contract_parser') and self.debugger.tracer.multi_contract_parser):
            # Try to find which contract this PC belongs to
            contract_info = self.debugger.tracer.multi_contract_parser.get_contract_at_address(contract_address)
        
        # Use contract-specific parser if found
        if contract_info and hasattr(contract_info, 'ethdebug_info'):
            parser = getattr(contract_info, 'parser', None)
            info_obj = contract_info.ethdebug_info
        else:
            # Fall back to main parser
            parser = None
            info_obj = None
            if hasattr(self.debugger, 'tracer') and self.debugger.tracer:
                parser = getattr(self.debugger.tracer, "ethdebug_parser", None)
                info_obj = getattr(self.debugger.tracer, "ethdebug_info", None)
        
        if info_obj and parser:
            si = info_obj.get_source_info(pc)
            if si:
                source_path, offset, _ = si
                l, c = parser.offset_to_line_col(source_path, offset)
                
                # Resolve absolute path
                if os.path.isabs(source_path):
                    abs_source_path = source_path
                else:
                    # Use contract's debug directory as base if available
                    if contract_info and hasattr(contract_info, 'debug_dir'):
                        base_dir = os.path.dirname(str(contract_info.debug_dir))
                        abs_source_path = os.path.normpath(os.path.join(base_dir, source_path))
                    elif hasattr(self, 'source_file') and self.source_file:
                        base_dir = os.path.dirname(self.source_file)
                        abs_source_path = os.path.normpath(os.path.join(base_dir, source_path))
                    else:
                        abs_source_path = os.path.abspath(source_path)
                
                # Check if file exists and try alternatives
                if not os.path.exists(abs_source_path) and hasattr(self, 'source_file') and self.source_file:
                    alternatives = [
                        os.path.join(os.path.dirname(self.source_file), source_path),
                        os.path.join(os.path.dirname(self.source_file), os.path.basename(source_path))
                    ]
                    for alt in alternatives:
                        if os.path.exists(alt):
                            abs_source_path = alt
                            break
                source = {
                    "name": os.path.basename(abs_source_path),
                    "path": abs_source_path,
                    "sourceReference": 0
                }
                line, col = l, c
        
        # Fallback to main source file if no specific source found
        if not source and hasattr(self, 'source_file') and self.source_file:
            source = {
                "name": os.path.basename(self.source_file),
                "path": self.source_file,
                "sourceReference": 0
            }
        
        return {
            "id": frame_id,
            "name": name,
            "line": line,
            "column": col,
            "source": source or {},
        }



    def scopes(self, request):
        scopes = [
            {"name": "Stack", "variablesReference": 1000, "expensive": False},
            {"name": "Parameters", "variablesReference": 1001, "expensive": False},
            {"name": "Step", "variablesReference": 1002, "expensive": False},
        ]
        self._response(request, True, {"scopes": scopes})

    def variables(self, request):
        ref = request.get("arguments", {}).get("variablesReference")
        vars_list: List[Dict[str, Any]] = []
        if not self.debugger or not self.debugger.current_trace:
            return self._response(request, True, {"variables": vars_list})

        if self.debugger.current_step >= len(self.debugger.current_trace.steps):
            return self._response(request, True, {"variables": vars_list})
        
        step = self.debugger.current_trace.steps[self.debugger.current_step]
                    
        if ref == 1000:
            # Stack
            for i, v in enumerate(step.stack):
                vars_list.append({"name": f"stack[{i}]", "value": hex(v) if isinstance(v, int) else str(v), "variablesReference": 0})
        
        elif ref == 1001:
            # Parameters
            if (self.debugger.current_function and self.debugger.current_function.args and
                (self.debugger.tracer.ethdebug_info or self.debugger.tracer.multi_contract_parser)):

                for param_name, param_value in self.debugger.current_function.args:
                    vars_list.append({"name": f"{param_name}", "value": str(param_value), "variablesReference": 0})
        elif ref == 1002:
            # Current step info
            vars_list.append({"name": "pc", "value": str(step.pc), "variablesReference": 0})
            vars_list.append({"name": "op", "value": step.op, "variablesReference": 0})
            vars_list.append({"name": "depth", "value": str(step.depth), "variablesReference": 0})
            vars_list.append({"name": "gas", "value": str(step.gas), "variablesReference": 0})
            vars_list.append({"name": "gasCost", "value": str(step.gas_cost), "variablesReference": 0})
            vars_list.append({"name": "step", "value": str(self.debugger.current_step), "variablesReference": 0})
        self._response(request, True, {"variables": vars_list})

    def evaluate(self, request):
        expr = request.get("arguments", {}).get("expression", "")
        result = "n/a"
        try:
            if expr.startswith("stack[") and expr.endswith("]") and self.debugger and self.debugger.current_trace:
                idx = int(expr[6:-1])
                if self.debugger.current_step >= len(self.debugger.current_trace.steps):
                    raise IndexError("Current step out of range")
                val = self.debugger.current_trace.steps[self.debugger.current_step].stack[idx]
                result = hex(val) if isinstance(val, int) else str(val)
            self._response(request, True, {"result": result, "variablesReference": 0})
        except Exception as e:
            self._response(request, False, message=str(e))

    def source(self, request):
        """Handle DAP 'source' request to load source file content"""
        try:
            args = request.get("arguments", {})
            source_ref = args.get("source", {})
            path = source_ref.get("path", "") if isinstance(source_ref, dict) else source_ref
            # Use the source file path from launch if available, otherwise use the requested path
            if hasattr(self, 'source_file') and self.source_file:
                source_path = self.source_file
            elif path:
                
                # Try to read the source file from the requested path
                if os.path.isabs(path):
                    # Absolute path
                    source_path = path
                else:
                    # Relative path - try to resolve from current working directory or debug info
                    if self.debugger and hasattr(self.debugger, 'tracer'):
                        # Try to get base path from debug info
                        if hasattr(self.debugger.tracer, 'ethdebug_parser') and self.debugger.tracer.ethdebug_parser:
                            base_dir = getattr(self.debugger.tracer.ethdebug_parser, 'debug_dir', os.getcwd())
                            if base_dir:
                                source_path = os.path.join(os.path.dirname(base_dir), path)
                            else:
                                source_path = os.path.join(os.getcwd(), path)
                        else:
                            source_path = os.path.join(os.getcwd(), path)
                    else:
                        source_path = os.path.join(os.getcwd(), path)
            else:
                self._response(request, False, message="No source path available")
                return
            
            # Read the file content
            if os.path.exists(source_path):
                with open(source_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self._response(request, True, {"content": content})
            else:
                self._response(request, False, message=f"Source file not found: {source_path}")
                
        except Exception as e:
            self._response(request, False, message=f"Error loading source: {str(e)}")

    # ---- Server loop ----
    def run(self):
        while True:
            msg = self._read()
            if msg is None:
                break
            if msg.get("type") != "request":
                continue
            cmd = msg.get("command")
            if cmd == "initialize":
                self.initialize(msg)
            elif cmd == "launch":
                self.launch(msg)
            elif cmd == "setBreakpoints":
                self.setBreakpoints(msg)
            elif cmd == "configurationDone":
                self._response(msg, True, {})
            elif cmd == "threads":
                self.threads(msg)
            elif cmd == "continue":
                self.continue_(msg)
            elif cmd == "next":
                self.next(msg)
            elif cmd == "stepIn":
                self.stepIn(msg)
            elif cmd == "stepOut":
                self.stepOut(msg)
            elif cmd == "stackTrace":
                self.stackTrace(msg)
            elif cmd == "scopes":
                self.scopes(msg)
            elif cmd == "variables":
                self.variables(msg)
            elif cmd == "evaluate":
                self.evaluate(msg)
            elif cmd == "source":
                self.source(msg)
            elif cmd == "disconnect" or cmd == "terminate":
                self._response(msg, True, {})
                break
            else:
                self._response(msg, False, message=f"Unsupported command: {cmd}")

def main():
    server = WalnutDAPServer()
    server.run()

if __name__ == "__main__":
    main()

