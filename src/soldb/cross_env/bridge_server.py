"""
Cross-Environment Debug Bridge Server

HTTP server that coordinates trace requests between SolDB (EVM) and StylusDB (Stylus).
"""

import json
import uuid
import threading
import time
import subprocess
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Callable, Any, List
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

from .protocol import (
    PROTOCOL_VERSION,
    ContractInfo,
    TraceRequest,
    TraceResponse,
    CrossEnvTrace,
    CrossEnvCall,
    CallArgument,
    SourceLocation,
    MessageType,
)
from .contract_registry import ContractRegistry


@dataclass
class PendingTraceRequest:
    """A trace request waiting for response."""
    request: TraceRequest
    timestamp: float
    callback: Optional[Callable[[TraceResponse], None]] = None


class TraceStore:
    """
    In-memory store for traces and pending requests.
    """

    def __init__(self, trace_ttl: int = 300):
        """
        Args:
            trace_ttl: Time-to-live for traces in seconds (default 5 minutes)
        """
        self._traces: Dict[str, CrossEnvTrace] = {}
        self._pending_requests: Dict[str, PendingTraceRequest] = {}
        self._trace_timestamps: Dict[str, float] = {}
        self._trace_ttl = trace_ttl
        self._lock = threading.Lock()

    def store_trace(self, trace: CrossEnvTrace) -> None:
        """Store a trace."""
        with self._lock:
            self._traces[trace.trace_id] = trace
            self._trace_timestamps[trace.trace_id] = time.time()

    def get_trace(self, trace_id: str) -> Optional[CrossEnvTrace]:
        """Retrieve a trace by ID."""
        with self._lock:
            return self._traces.get(trace_id)

    def add_pending_request(
        self,
        request: TraceRequest,
        callback: Optional[Callable[[TraceResponse], None]] = None
    ) -> str:
        """Add a pending trace request."""
        with self._lock:
            self._pending_requests[request.request_id] = PendingTraceRequest(
                request=request,
                timestamp=time.time(),
                callback=callback,
            )
        return request.request_id

    def get_pending_request(self, request_id: str) -> Optional[PendingTraceRequest]:
        """Get a pending request."""
        with self._lock:
            return self._pending_requests.get(request_id)

    def complete_request(self, request_id: str, response: TraceResponse) -> bool:
        """Complete a pending request with a response."""
        with self._lock:
            pending = self._pending_requests.pop(request_id, None)
            if pending and pending.callback:
                pending.callback(response)
                return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired traces and requests. Returns count of removed items."""
        now = time.time()
        removed = 0
        with self._lock:
            # Clean up old traces
            expired_traces = [
                tid for tid, ts in self._trace_timestamps.items()
                if now - ts > self._trace_ttl
            ]
            for tid in expired_traces:
                del self._traces[tid]
                del self._trace_timestamps[tid]
                removed += 1

            # Clean up old pending requests (60 second timeout)
            expired_requests = [
                rid for rid, req in self._pending_requests.items()
                if now - req.timestamp > 60
            ]
            for rid in expired_requests:
                del self._pending_requests[rid]
                removed += 1

        return removed


class BridgeRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the bridge server."""

    # Reference to shared state (set by server)
    registry: ContractRegistry = None
    trace_store: TraceStore = None
    trace_handlers: Dict[str, Callable] = None
    trace_commands: Dict[str, str] = None  # address -> command template

    def log_message(self, format: str, *args) -> None:
        """Override to use custom logging or suppress."""
        if self.server.verbose:
            print(f"[Bridge] {args[0]} {args[1]} {args[2]}")

    def _send_json_response(self, data: Dict, status: int = 200) -> None:
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_error_response(self, message: str, status: int = 400) -> None:
        """Send an error response."""
        self._send_json_response({
            "status": "error",
            "error_message": message,
        }, status)

    def _read_json_body(self) -> Optional[Dict]:
        """Read and parse JSON body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length)
            return json.loads(body.decode())
        except Exception as e:
            return None

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self._handle_health()
        elif path == "/contracts":
            self._handle_list_contracts()
        elif path.startswith("/contract/"):
            address = path.split("/")[-1]
            self._handle_get_contract(address)
        elif path.startswith("/trace/"):
            trace_id = path.split("/")[-1]
            self._handle_get_trace(trace_id)
        elif path == "/":
            self._handle_info()
        else:
            self._send_error_response("Not found", 404)

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        body = self._read_json_body()
        if body is None:
            self._send_error_response("Invalid JSON body")
            return

        if path == "/register":
            self._handle_register_contract(body)
        elif path == "/request-trace":
            self._handle_trace_request(body)
        elif path == "/submit-trace":
            self._handle_submit_trace(body)
        elif path == "/respond-trace":
            self._handle_trace_response(body)
        else:
            self._send_error_response("Not found", 404)

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/contract/"):
            address = path.split("/")[-1]
            self._handle_unregister_contract(address)
        else:
            self._send_error_response("Not found", 404)

    def _handle_info(self) -> None:
        """Return server info."""
        self._send_json_response({
            "name": "Cross-Environment Debug Bridge",
            "protocol_version": PROTOCOL_VERSION,
            "endpoints": [
                "GET /health",
                "GET /contracts",
                "GET /contract/{address}",
                "GET /trace/{trace_id}",
                "POST /register",
                "POST /request-trace",
                "POST /submit-trace",
                "POST /respond-trace",
                "DELETE /contract/{address}",
            ]
        })

    def _handle_health(self) -> None:
        """Health check endpoint."""
        self._send_json_response({
            "status": "healthy",
            "protocol_version": PROTOCOL_VERSION,
            "contracts_registered": len(self.registry.get_all_contracts()),
        })

    def _handle_list_contracts(self) -> None:
        """List all registered contracts."""
        contracts = self.registry.get_all_contracts()
        self._send_json_response({
            "contracts": [c.to_dict() for c in contracts],
            "count": len(contracts),
        })

    def _handle_get_contract(self, address: str) -> None:
        """Get a specific contract."""
        contract = self.registry.get(address)
        if contract:
            self._send_json_response(contract.to_dict())
        else:
            self._send_error_response(f"Contract not found: {address}", 404)

    def _handle_register_contract(self, body: Dict) -> None:
        """Register a contract."""
        try:
            contract = ContractInfo.from_dict(body)
            if not contract.address:
                self._send_error_response("Address is required")
                return
            if not contract.environment:
                self._send_error_response("Environment is required (evm or stylus)")
                return

            self.registry.register(contract)
            self._send_json_response({
                "status": "registered",
                "contract": contract.to_dict(),
            })
        except Exception as e:
            self._send_error_response(f"Failed to register contract: {e}")

    def _handle_unregister_contract(self, address: str) -> None:
        """Unregister a contract."""
        contract = self.registry.unregister(address)
        if contract:
            self._send_json_response({
                "status": "unregistered",
                "address": address,
            })
        else:
            self._send_error_response(f"Contract not found: {address}", 404)

    def _get_rust_toolchain(self, project_dir: str) -> str:
        toolchain_file = os.path.join(project_dir, "rust-toolchain.toml")
        if not os.path.exists(toolchain_file):
            return "stable"
        try:
            import tomllib
            with open(toolchain_file, "rb") as f:
                data = tomllib.load(f)
            return data.get("toolchain", {}).get("channel", "stable")
        except Exception:
            return "stable"


    def _ensure_wasm_target(self, toolchain: str):
        result = subprocess.run(
            f"rustup target list --toolchain {toolchain}",
            shell=True,
            capture_output=True,
            text=True,
        )

        if "wasm32-unknown-unknown (installed)" not in result.stdout:
            subprocess.run(
                f"rustup target add wasm32-unknown-unknown --toolchain {toolchain}",
                shell=True,
                check=True,
            )


    def _prepare_rustup_env(self, project_dir: str) -> dict:
        """Prepare environment for rustup/cargo with correct PATH priority."""
        env = os.environ.copy()
        toolchain = self._get_rust_toolchain(project_dir)

        env["RUSTUP_TOOLCHAIN"] = toolchain
        env["CARGO_TARGET_DIR"] = os.path.join(project_dir, "target")

        # Prioritize ~/.cargo/bin over system paths (e.g., Homebrew)
        # This ensures rustup's cargo/rustc are used instead of Homebrew's
        cargo_bin = os.path.expanduser("~/.cargo/bin")
        current_path = env.get("PATH", "")

        # Remove cargo_bin from current position and add it at the beginning
        path_parts = [p for p in current_path.split(":") if p != cargo_bin]
        env["PATH"] = f"{cargo_bin}:{':'.join(path_parts)}"

        return env

    def rustup_override_set(self, project_dir: str, toolchain: str):
        try:
            subprocess.run(
                ["rustup", "override", "set", toolchain],
                cwd=project_dir,
                check=True
            )
            print(f"[Bridge] Rust override set: {toolchain} in {project_dir}")
        except subprocess.CalledProcessError as e:
            print(f"[Bridge] ERROR: Failed to set rustup override: {e}")

    def _invoke_soldb_trace(
        self,
        request: TraceRequest,
        contract: ContractInfo,
    ) -> Optional[CrossEnvTrace]:
        """
        Invoke soldb simulate command for EVM/Solidity contract.

        Command: soldb simulate ADDRESS --raw-data CALLDATA --from CALLER --rpc RPC --ethdebug-dir ADDR:NAME:PATH

        Args:
            request: The trace request
            contract: The target contract info (must have debug_dir)

        Returns:
            CrossEnvTrace if successful, None otherwise
        """
        # print("=" * 80)
        # print(f"[Bridge] ===== INVOKING SOLDB TRACE (EVM/Solidity) =====")
        # print(f"[Bridge] Contract: {contract.address} ({contract.name})")
        # print(f"[Bridge] Request ID: {request.request_id}")
        # print(f"[Bridge] Calldata: {request.calldata}")
        # print(f"[Bridge] Caller: {request.caller_address}")
        # print(f"[Bridge] Target: {request.target_address}")
        # print(f"[Bridge] Value: {request.value} wei")
        # print(f"[Bridge] Block: {request.block_number}")
        # print(f"[Bridge] Project path: {contract.project_path}")
        # print(f"[Bridge] Debug dir: {contract.debug_dir}")
        # print("=" * 80)

        if not contract.debug_dir:
            print(f"[Bridge] ERROR: No debug_dir configured for contract")
            return None

        if not contract.project_path:
            print(f"[Bridge] ERROR: No project_path configured for contract")
            return None

        # Determine working directory and ethdebug path
        cwd = contract.project_path
        # debug_dir is relative to project_path
        ethdebug_path = contract.debug_dir

        # Build soldb simulate command
        # Format: soldb simulate ADDRESS --raw-data DATA --from CALLER --rpc RPC --ethdebug-dir ADDR:NAME:PATH --json
        cmd = ["soldb", "simulate", contract.address]

        if request.calldata:
            cmd.extend(["--raw-data", request.calldata])
        if request.caller_address:
            cmd.extend(["--from", request.caller_address])
        if request.value and request.value > 0:
            cmd.extend(["--value", str(request.value)])
        if request.block_number:
            cmd.extend(["--block", str(request.block_number)])
        # RPC endpoint - try to get from environment or use default
        rpc_url = os.environ.get("RPC_URL", "http://localhost:8547")
        cmd.extend(["--rpc", rpc_url])
        # ethdebug-dir format: ADDRESS:NAME:PATH (PATH is relative to cwd)
        ethdebug_dir = f"{contract.address}:{contract.name}:{ethdebug_path}"
        cmd.extend(["--ethdebug-dir", ethdebug_dir])
        # Request JSON output
        cmd.append("--json")

        # print(f"[Bridge] Command: {' '.join(cmd)}")
        # print(f"[Bridge] CWD: {cwd}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=cwd,  # Run from project_path
            )

            if result.stderr:
                print(f"[Bridge] soldb stderr: {result.stderr[:500]}")

            if result.returncode != 0:
                print(f"[Bridge] ERROR: soldb simulate failed")
                return None

            # Parse JSON output
            if result.stdout:
                try:
                    trace_data = json.loads(result.stdout)
                    # print(f"[Bridge] soldb stdout: {trace_data}")
                    # Convert to CrossEnvTrace
                    trace = self._convert_soldb_trace_to_cross_env(trace_data, request, contract)
                    if trace:
                        trace.trace_id = request.request_id
                        self.trace_store.store_trace(trace)
                    return trace

                except json.JSONDecodeError as e:
                    print(f"[Bridge] ERROR: Failed to parse soldb JSON: {e}")
                    return None
            else:
                print(f"[Bridge] WARNING: No stdout from soldb")
                return None

        except subprocess.TimeoutExpired:
            print(f"[Bridge] ERROR: soldb simulate timed out")
            return None
        except Exception as e:
            return None

    def _convert_soldb_trace_to_cross_env(
        self,
        soldb_trace: Dict,
        request: TraceRequest,
        contract: ContractInfo,
    ) -> Optional[CrossEnvTrace]:
        """
        Convert soldb trace JSON to CrossEnvTrace format.

        soldb --json output format:
        {
          "status": "success",
          "traceCall": {
            "type": "ENTRY",
            "functionName": "Contract::runtime_dispatcher",
            "callId": 0,
            "calls": [
              {
                "type": "CALL",
                "functionName": "add(uint256,uint256)",
                "callId": 1,
                "parentCallId": 0,
                "calls": [...],
                ...
              }
            ],
            ...
          }
        }
        """
        try:
            calls = []

            # Get the root traceCall object
            trace_call = soldb_trace.get("traceCall", {})
            if not trace_call:
                print(f"[Bridge] WARNING: No 'traceCall' found in soldb output")
                return None

            # TODO move this function to soldb/utils.py
            def _parse_gas(val):
                """Convert gas value (int or hex string) to int."""
                if val is None:
                    return None
                if isinstance(val, int):
                    return val
                if isinstance(val, str):
                    try:
                        return int(val, 16) if val.startswith("0x") else int(val)
                    except ValueError:
                        return None
                return None

            # Recursive function to extract calls from nested structure
            def extract_calls(call_obj: Dict, parent_id: Optional[int] = None) -> List[CrossEnvCall]:
                result = []

                call_id = call_obj.get("callId", 0)
                func_name = call_obj.get("functionName", "function_0x")
                call_type = call_obj.get("type", "CALL")

                # Extract input arguments if available
                args = []
                inputs = call_obj.get("inputs", {})
                if inputs:
                    arg_names = inputs.get("argumentsName", [])
                    arg_types = inputs.get("argumentsType", [])
                    arg_values = inputs.get("argumentsDecodedValue", [])
                    for i in range(len(arg_names)):
                        args.append(CallArgument(
                            name=arg_names[i] if i < len(arg_names) else "",
                            type=arg_types[i] if i < len(arg_types) else "",
                            value=str(arg_values[i]) if i < len(arg_values) else "",
                        ))

                # Extract return value if available
                outputs = call_obj.get("outputs", {})
                return_value = None
                if outputs:
                    ret_values = outputs.get("argumentsDecodedValue", [])
                    if ret_values:
                        return_value = str(ret_values[0]) if len(ret_values) == 1 else str(ret_values)

                status = call_obj.get("isRevertedFrame", False)
                # print(f"[Bridge] soldb call status: {status}")
                cross_call = CrossEnvCall(
                    call_id=call_id,
                    parent_call_id=parent_id,
                    environment="evm",
                    contract_address=call_obj.get("address", contract.address),
                    function_name=func_name,
                    function_selector=call_obj.get("selector"),
                    source_location=None,
                    args=args,
                    return_data=call_obj.get("output"),
                    return_value=return_value,
                    gas_used=_parse_gas(call_obj.get("gasUsed")),
                    success=not status,
                    error=call_obj.get("error"),
                    call_type=call_type.lower(),
                    children=[],
                )
                result.append(cross_call)

                # Recursively process nested calls
                nested_calls = call_obj.get("calls", [])
                for nested in nested_calls:
                    child_calls = extract_calls(nested, call_id)
                    result.extend(child_calls)

                return result

            # Extract all calls starting from root
            calls = extract_calls(trace_call)

            trace = CrossEnvTrace(
                trace_id=request.request_id,
                transaction_hash=request.transaction_hash,
                root_call=calls[0] if calls else None,
                calls=calls,
                from_address=request.caller_address,
                to_address=request.target_address,
                value=request.value,
                success=soldb_trace.get("status") == "success",
            )

            return trace

        except Exception as e:
            import traceback
            traceback.print_exc()
            return None

    def _invoke_stylus_trace(
        self,
        request: TraceRequest,
        contract: ContractInfo,
    ) -> Optional[CrossEnvTrace]:
        """
        Invoke Stylus usertrace command in SIMULATE mode and read trace from output file.

        Command: cargo stylus-beta usertrace --simulate --data <calldata> --to <addr> --from <addr> [--value <wei>]

        Note: TX mode is NOT supported via bridge because the tx hash exists only on EVM side.
        The bridge always uses simulate mode with calldata extracted from the EVM trace.

        Args:
            request: The trace request (must have calldata, target_address, caller_address)
            contract: The target contract info (must have project_path pointing to Stylus project root)

        Returns:
            CrossEnvTrace if successful, None otherwise
        """
        # Stylus trace output file
        STYLUS_TRACE_FILE = "/tmp/lldb_function_trace.json"

        # print("=" * 80)
        # print(f"[Bridge] ===== INVOKING STYLUS TRACE (SIMULATE MODE) =====")
        # print(f"[Bridge] Contract: {contract.address} ({contract.name})")
        # print(f"[Bridge] Request ID: {request.request_id}")
        # print(f"[Bridge] Calldata: {request.calldata}")
        # print(f"[Bridge] Caller: {request.caller_address}")
        # print(f"[Bridge] Target: {request.target_address}")
        # print(f"[Bridge] Value: {request.value} wei")
        # print("=" * 80)

        # Get project_path - can be explicit or inferred from lib_path
        cwd = contract.project_path

        # Try to infer project_path from lib_path if not set
        # lib_path is typically: /path/to/project/target/wasm32-unknown-unknown/release/contract.wasm
        if not cwd and contract.lib_path:
            lib_path = contract.lib_path
            # Find 'target' directory and go to parent
            if '/target/' in lib_path:
                cwd = lib_path.split('/target/')[0]

        if not cwd:
            print(f"[Bridge] ERROR: Cannot determine project_path for Stylus contract")
            print(f"[Bridge] Please set 'project_path' in stylus-contracts.json or provide lib_path")
            return None
        
        if not os.path.isdir(cwd):
            print(f"[Bridge] ERROR: Project directory does not exist: {cwd}")
            return None

        # Always use 'cargo stylus-beta' command (not the binary path directly)
        stylus_cmd = "cargo stylus-beta"
        toolchain = self._get_rust_toolchain(cwd)
        if toolchain.startswith("1.") and toolchain.count(".") == 1:
            toolchain = toolchain + ".0"

        env = self._prepare_rustup_env(cwd) 
        
        result = subprocess.run(
            f"rustup toolchain list | grep {toolchain}",
            shell=True,
            capture_output=True,
            text=True,
            env=env,
        )
        
        if result.returncode == 0:
            cmd_prefix = f"+{toolchain}"
        else:
            cmd_prefix = ""
            self.rustup_override_set(cwd, toolchain)
            self._ensure_wasm_target(toolchain)
            env = self._prepare_rustup_env(cwd)

        try:
            result = subprocess.run(
                "which rustc",
                shell=True,
                capture_output=True,
                text=True,
                env=env,
            )
            if result.returncode == 0:
                result = subprocess.run(
                    "rustc --version",
                    shell=True,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                print(f"[Bridge] rustc version: {result.stdout.strip()}")
                
                # Rustc target list
                result = subprocess.run(
                    "rustc --print target-list | grep wasm32",
                    shell=True,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                print(f"[Bridge] Available wasm targets: {result.stdout.strip()}")
            else:
                print(f"[Bridge] WARNING: rustc not found in PATH")
        except Exception as e:
            print(f"[Bridge] WARNING: Failed to check rustc: {e}")

        try:
            result = subprocess.run(
                "which cargo",
                shell=True,
                capture_output=True,
                text=True,
                env=env,
            )
            if result.returncode == 0:
                result = subprocess.run(
                    "cargo --version",
                    shell=True,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                print(f"[Bridge] cargo version: {result.stdout.strip()}")
            else:
                print(f"[Bridge] WARNING: cargo not found in PATH")
        except Exception as e:
            print(f"[Bridge] WARNING: Failed to check cargo: {e}")
        
        stylus_cmd = f"rustup run {toolchain} {stylus_cmd}"
        
        # Build simulate command
        # cargo stylus-beta usertrace --simulate --data <calldata> --to <addr> --from <addr> [--value <wei>]
        cmd = f"cd {cwd} && {stylus_cmd} usertrace --simulate"
        cmd += f" --data {request.calldata or '0x'}"
        cmd += f" --to {request.target_address}"
        cmd += f" --from {request.caller_address or '0x0000000000000000000000000000000000000000'}"
        if request.value:
            cmd += f" --value {request.value}"

        try:
            # Extract working directory from command (if cd is used)
            import re
            cwd_match = re.search(r'cd\s+([^\s&|;]+)', cmd)
            if cwd_match:
                cwd = cwd_match.group(1)
            else:
                cwd = contract.project_path or os.getcwd()
            
            env = self._prepare_rustup_env(cwd)

            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,  # 60 second timeout
                    cwd=cwd,
                    env=env,
                )
                print(f"[Bridge] Subprocess completed successfully")
            except subprocess.TimeoutExpired as e:
                return None
            except Exception as e:
                print(f"[Bridge] ERROR: Exception during subprocess execution: {e}")
                import traceback
                traceback.print_exc()
                return None
            
            if result.returncode != 0:
                return None
            
            if result.stderr:
                print(f"[Bridge] stderr output (first 500 chars):")
                print(f"  {result.stderr[:500]}")

            if not os.path.exists(STYLUS_TRACE_FILE):
                return None

            try:
                with open(STYLUS_TRACE_FILE, 'r') as f:
                    trace_content = f.read()

                trace_dict = json.loads(trace_content)

                # Convert to CrossEnvTrace format
                trace = self._convert_stylus_trace_to_cross_env(trace_dict, request, contract)

                if trace:
                    trace.trace_id = request.request_id
                    self.trace_store.store_trace(trace)
                    return trace
                else:
                    return None

            except json.JSONDecodeError as e:
                return None
            except Exception as e:
                print(f"[Bridge] ERROR: Failed to read trace file: {e}")
                import traceback
                traceback.print_exc()
                return None
            
        except Exception as e:
            print(f"[Bridge] ERROR: Exception in _invoke_stylus_trace: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _convert_stylus_trace_to_cross_env(
        self,
        stylus_trace: Dict,
        request: TraceRequest,
        contract: ContractInfo,
    ) -> Optional[CrossEnvTrace]:
        """
        Convert Stylus trace JSON format to CrossEnvTrace.

        Args:
            stylus_trace: Raw JSON dict from /tmp/lldb_function_trace.json
            request: The original trace request
            contract: The target contract info

        Returns:
            CrossEnvTrace if conversion successful, None otherwise
        """
        
        try:
            calls = []
            call_id_counter = 1

            # Parse Stylus trace format
            # The trace can be either:
            # 1. A list of calls directly: [{call_id, function, file, line, args}, ...]
            # 2. A dict with "function_calls" or "calls" key
            if isinstance(stylus_trace, list):
                # Direct list of calls
                raw_calls = stylus_trace
                print(f"[Bridge] Trace is a list with {len(raw_calls)} call(s)")
            else:
                # Dict format
                raw_calls = stylus_trace.get("function_calls", stylus_trace.get("calls", []))

            # Stylus trace is a FLAT list with parent_call_id references
            # We need to convert it to a hierarchical structure

            # First pass: create all CrossEnvCall objects
            call_map = {}  # call_id -> CrossEnvCall

            for raw_call in raw_calls:
                call_id = raw_call.get("call_id", call_id_counter)
                parent_id = raw_call.get("parent_call_id")  # 0 means root

                # Extract function info
                func_name = raw_call.get("function", raw_call.get("name", raw_call.get("function_name", "unknown")))
                func_selector = raw_call.get("selector", raw_call.get("function_selector"))

                # Extract source location
                source_loc = None
                if "source_location" in raw_call:
                    src = raw_call["source_location"]
                    source_loc = SourceLocation(
                        file=src.get("file", ""),
                        line=src.get("line", 0),
                        column=src.get("column"),
                    )
                elif "file" in raw_call and "line" in raw_call:
                    source_loc = SourceLocation(
                        file=raw_call["file"],
                        line=raw_call["line"],
                        column=raw_call.get("column"),
                    )

                # Extract arguments
                args = []
                raw_args = raw_call.get("args", raw_call.get("arguments", []))
                for arg in raw_args:
                    if isinstance(arg, dict):
                        args.append(CallArgument(
                            name=arg.get("name", ""),
                            type=arg.get("type", ""),
                            value=str(arg.get("value", "")),
                        ))
                    else:
                        args.append(CallArgument(name="", type="", value=str(arg)))

                # Determine success: explicit success field, or infer from error field
                has_error = raw_call.get("error", False)
                call_success = raw_call.get("success", not has_error)

                # Get error message: use error_message if present, otherwise None
                error_msg = raw_call.get("error_message")

                cross_call = CrossEnvCall(
                    call_id=call_id,
                    parent_call_id=parent_id if parent_id and parent_id != 0 else None,
                    environment="stylus",
                    contract_address=raw_call.get("contract_address", contract.address),
                    function_name=func_name,
                    function_selector=func_selector,
                    source_location=source_loc,
                    args=args,
                    return_data=raw_call.get("return_data"),
                    return_value=raw_call.get("return_value"),
                    gas_used=raw_call.get("gas_used"),
                    success=call_success,
                    error=error_msg,
                    call_type=raw_call.get("call_type", "internal"),
                    children=[],  # Will be populated in second pass
                )

                call_map[call_id] = cross_call
                calls.append(cross_call)

            # Second pass: build children lists based on parent_call_id
            for cross_call in calls:
                parent_id = cross_call.parent_call_id
                if parent_id and parent_id in call_map:
                    call_map[parent_id].children.append(cross_call)

            print(f"[Bridge] Built hierarchy: {len(calls)} calls, {sum(1 for c in calls if not c.parent_call_id)} root calls")

            # Determine trace-level success from status field or by checking if any call has an error
            trace_status = stylus_trace.get("status", "success") if isinstance(stylus_trace, dict) else "success"
            trace_success = trace_status != "error"
            # Also check if any call failed
            if trace_success:
                trace_success = all(c.success for c in calls)

            # Get trace-level error message if present
            trace_error = stylus_trace.get("error_message") if isinstance(stylus_trace, dict) else None

            # Create CrossEnvTrace
            trace = CrossEnvTrace(
                trace_id=request.request_id,
                transaction_hash=request.transaction_hash,
                root_call=calls[0] if calls else None,
                calls=calls,
                from_address=request.caller_address,
                to_address=request.target_address,
                value=request.value,
                success=trace_success,
                error=trace_error,
            )

            return trace

        except Exception as e:
            print(f"[Bridge] ERROR converting Stylus trace: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _handle_trace_request(self, body: Dict) -> None:
        """
        Handle a trace request from one environment.

        If a trace handler is registered for the target environment,
        it will be invoked to generate the trace.
        """
        try:
            request = TraceRequest.from_dict(body)
            if not request.request_id:
                request.request_id = str(uuid.uuid4())

            # print(f"[Bridge] Received trace request:")
            # print(f"  Request ID: {request.request_id}")
            # print(f"  Target: {request.target_address}")
            # print(f"  Caller: {request.caller_address}")
            # print(f"  Calldata: {request.calldata}")
            # print(f"  Value: {request.value} wei")
            # print(f"  Depth: {request.depth}")

            # Determine target environment
            target_contract = self.registry.get(request.target_address)
            if not target_contract:
                self._send_error_response(
                    f"Contract not registered: {request.target_address}",
                    404
                )
                return

            target_env = target_contract.environment

            # Check if we have a handler for this environment
            handler = self.trace_handlers.get(target_env) if self.trace_handlers else None
            if handler:
                # Invoke the handler to get the trace
                try:
                    trace = handler(request, target_contract)
                    # Set response status based on trace success (transaction outcome)
                    response_status = "success" if trace.success else "error"
                    response = TraceResponse(
                        request_id=request.request_id,
                        status=response_status,
                        trace=trace,
                    )
                except Exception as e:
                    response = TraceResponse(
                        request_id=request.request_id,
                        status="error",
                        error_message=str(e),
                    )
                self._send_json_response(response.to_dict())
            elif target_env == "evm":
                # Automatically invoke soldb trace command
                trace = self._invoke_soldb_trace(request, target_contract)
                if trace:
                    # Set response status based on trace success (transaction outcome)
                    response_status = "success" if trace.success else "error"
                    response = TraceResponse(
                        request_id=request.request_id,
                        status=response_status,
                        trace=trace,
                    )
                    # print(f"[Bridge] Trace generated {response.to_dict()}")
                    self._send_json_response(response.to_dict())
                else:
                    # Command failed - store as pending
                    self.trace_store.add_pending_request(request)
                    self._send_json_response({
                        "request_id": request.request_id,
                        "status": "pending",
                        "message": f"Request queued for {target_env} environment (Solidity trace generation failed)",
                        "target_environment": target_env,
                    })
            elif target_env == "stylus":
                # Automatically invoke Stylus trace command
                trace = self._invoke_stylus_trace(request, target_contract)
                if trace:
                    # Set response status based on trace success (transaction outcome)
                    response_status = "success" if trace.success else "error"
                    response = TraceResponse(
                        request_id=request.request_id,
                        status=response_status,
                        trace=trace,
                    )
                    self._send_json_response(response.to_dict())
                else:
                    # Command failed - store as pending
                    self.trace_store.add_pending_request(request)
                    self._send_json_response({
                        "request_id": request.request_id,
                        "status": "pending",
                        "message": f"Request queued for {target_env} environment (Stylus trace generation failed or not available)",
                        "target_environment": target_env,
                    })
            else:
                # No handler - store as pending request
                self.trace_store.add_pending_request(request)
                self._send_json_response({
                    "request_id": request.request_id,
                    "status": "pending",
                    "message": f"Request queued for {target_env} environment",
                    "target_environment": target_env,
                })

        except Exception as e:
            import traceback
            traceback.print_exc()
            self._send_error_response(f"Failed to process trace request: {e}")

    def _handle_submit_trace(self, body: Dict) -> None:
        """Submit a completed trace."""
        try:
            trace = CrossEnvTrace.from_dict(body)
            if not trace.trace_id:
                trace.trace_id = str(uuid.uuid4())

            self.trace_store.store_trace(trace)
            self._send_json_response({
                "status": "stored",
                "trace_id": trace.trace_id,
            })
        except Exception as e:
            self._send_error_response(f"Failed to store trace: {e}")

    def _handle_trace_response(self, body: Dict) -> None:
        """Handle a trace response for a pending request."""
        try:
            response = TraceResponse.from_dict(body)
            if self.trace_store.complete_request(response.request_id, response):
                self._send_json_response({
                    "status": "completed",
                    "request_id": response.request_id,
                })
            else:
                self._send_json_response({
                    "status": "not_found",
                    "message": f"No pending request found: {response.request_id}",
                })
        except Exception as e:
            self._send_error_response(f"Failed to process trace response: {e}")

    def _handle_get_trace(self, trace_id: str) -> None:
        """Get a stored trace."""
        trace = self.trace_store.get_trace(trace_id)
        if trace:
            self._send_json_response(trace.to_dict())
        else:
            self._send_error_response(f"Trace not found: {trace_id}", 404)


class CrossEnvBridgeServer:
    """
    Cross-Environment Debug Bridge Server.

    Provides HTTP endpoints for:
    - Contract registration (EVM and Stylus)
    - Trace requests between environments
    - Trace submission and retrieval
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        verbose: bool = False,
    ):
        self.host = host
        self.port = port
        self.verbose = verbose

        # Shared state
        self.registry = ContractRegistry()
        self.trace_store = TraceStore()
        self.trace_handlers: Dict[str, Callable] = {}
        self.trace_commands: Dict[str, str] = {}  # address -> command template

        # Server instance
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False

    def register_trace_handler(
        self,
        environment: str,
        handler: Callable[[TraceRequest, ContractInfo], CrossEnvTrace]
    ) -> None:
        """
        Register a handler for generating traces in a specific environment.

        The handler will be called when a trace request targets a contract
        in the specified environment.

        Args:
            environment: "evm" or "stylus"
            handler: Callable that takes (TraceRequest, ContractInfo) and returns CrossEnvTrace
        """
        self.trace_handlers[environment] = handler

    def _create_handler_class(self):
        """Create a handler class with access to server state."""
        server = self

        class Handler(BridgeRequestHandler):
            registry = server.registry
            trace_store = server.trace_store
            trace_handlers = server.trace_handlers
            trace_commands = server.trace_commands
            bridge_server = server  # Reference to CrossEnvBridgeServer instance

        return Handler

    def _cleanup_loop(self) -> None:
        """Periodically clean up expired traces."""
        while self._running:
            time.sleep(60)  # Run every minute
            if self._running:
                removed = self.trace_store.cleanup_expired()
                if removed > 0 and self.verbose:
                    print(f"[Bridge] Cleaned up {removed} expired items")

    def start(self, blocking: bool = True) -> None:
        """
        Start the bridge server.

        Args:
            blocking: If True, blocks until server is stopped.
                     If False, runs in background thread.
        """
        handler_class = self._create_handler_class()
        self._server = HTTPServer((self.host, self.port), handler_class)
        self._server.verbose = self.verbose
        self._running = True

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        if self.verbose:
            print(f"[Bridge] Cross-Environment Debug Bridge started on http://{self.host}:{self.port}")
            print(f"[Bridge] Protocol version: {PROTOCOL_VERSION}")

        if blocking:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._server_thread.start()

    def stop(self) -> None:
        """Stop the bridge server."""
        self._running = False
        if self._server:
            self._server.shutdown()
            if self.verbose:
                print("[Bridge] Server stopped")

    def get_url(self) -> str:
        """Get the server URL."""
        return f"http://{self.host}:{self.port}"


def run_bridge_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    verbose: bool = True,
    config_file: Optional[str] = None,
) -> None:
    """
    Run the cross-environment debug bridge server.

    Args:
        host: Host to bind to
        port: Port to listen on
        verbose: Enable verbose logging
        config_file: Optional path to contracts configuration file
    """
    server = CrossEnvBridgeServer(host=host, port=port, verbose=verbose)

    # Load configuration if provided
    if config_file:
        try:
            count = server.registry.load_from_file(config_file)
            print(f"[Bridge] Loaded {count} contracts from {config_file}")
        except Exception as e:
            print(f"[Bridge] Warning: Failed to load config: {e}")

    print(f"Cross-Environment Debug Bridge")
    print(f"=" * 40)
    print(f"URL: http://{host}:{port}")
    print(f"Protocol: {PROTOCOL_VERSION}")
    print(f"")
    print(f"Endpoints:")
    print(f"  GET  /health           - Health check")
    print(f"  GET  /contracts        - List registered contracts")
    print(f"  POST /register         - Register a contract")
    print(f"  POST /request-trace    - Request trace from environment")
    print(f"  POST /submit-trace     - Submit completed trace")
    print(f"")
    print(f"Press Ctrl+C to stop")
    print(f"=" * 40)

    server.start(blocking=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cross-Environment Debug Bridge Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--config", help="Path to contracts configuration file")
    parser.add_argument("--quiet", action="store_true", help="Suppress request logging")

    args = parser.parse_args()
    run_bridge_server(
        host=args.host,
        port=args.port,
        verbose=not args.quiet,
        config_file=args.config,
    )
