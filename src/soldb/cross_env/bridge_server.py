"""
Cross-Environment Debug Bridge Server

HTTP server that coordinates trace requests between SolDB (EVM) and StylusDB (Stylus).
"""

import json
import uuid
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

from .protocol import (
    PROTOCOL_VERSION,
    ContractInfo,
    TraceRequest,
    TraceResponse,
    CrossEnvTrace,
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

            # Determine target environment
            target_contract = self.registry.get(request.target_address)
            if not target_contract:
                self._send_json_response({
                    "request_id": request.request_id,
                    "status": "not_found",
                    "error_message": f"Contract not registered: {request.target_address}",
                })
                return

            target_env = target_contract.environment

            # Check if we have a handler for this environment
            handler = self.trace_handlers.get(target_env) if self.trace_handlers else None
            if handler:
                # Invoke the handler to get the trace
                try:
                    trace = handler(request, target_contract)
                    response = TraceResponse(
                        request_id=request.request_id,
                        status="success",
                        trace=trace,
                    )
                except Exception as e:
                    response = TraceResponse(
                        request_id=request.request_id,
                        status="error",
                        error_message=str(e),
                    )
                self._send_json_response(response.to_dict())
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
